"""Corporate Redesigned, the Restore tests sub tab of the Datastore view (round 11): the five parts,
the state every guest is listed under and the field that decides it, the weekly run and the live
tests, and every write against the request the classic panel sends.

Runtime tests drive the built bundle in headless Chromium against the guard fake of
tests/test_corp_redesigned_guard_ui.py with the restore test reads (RT_READS). The counterproof
runs this file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>. The routes are
tested in tests/test_recovery_report.py and tests/test_recovery_assurance.py.
LW Nov 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, FIXED, RT_ASSURANCE, RT_READS, RT_REPORT, RT_SETTINGS, RT_STATUS,
                                           _GuardApp, _GuardServer, _rt_row)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
DASHES = (chr(0x2014), chr(0x2013))

WRITES = {
    ('PUT', '/api/clusters/c1/recovery-settings'): (200, {'success': True, 'cluster': RT_SETTINGS['cluster']}),
    ('PUT', '/api/clusters/c1/recovery-settings/rules'): (200, {'success': True, 'rule': None}),
    ('DELETE', '/api/clusters/c1/recovery-settings/rules/guest/101'): (200, {'success': True}),
    ('DELETE', '/api/clusters/c1/recovery-settings/rules/tag/web'): (200, {'success': True}),
    ('POST', '/api/clusters/c1/recovery-confirmations'): (200, {'success': True, 'id': 'abcdef0123456789'}),
    ('DELETE', '/api/clusters/c1/recovery-confirmations/0123456789abcdef'): (200, {'success': True}),
    ('POST', '/api/recovery-evidence/verify'): (200, {'signature_valid': True, 'audit_chain': 'present'}),
    ('PUT', '/api/pbs/verify-schedule'): (200, RT_STATUS['policy']),
}


def _reads(over=None):
    r = dict(RT_READS)
    r.update(WRITES)
    r[('GET', '/api/clusters/c1/backup-verify/active')] = (200, {})
    r[('GET', '/api/clusters/c1/recovery-report/100')] = (200, GUEST_100)
    r.update(over or {})
    return r


GUEST_100 = {'guest': dict(RT_REPORT['guests'][2], last_checks=[{'check': 'agent', 'target': '', 'ok': True, 'detail': 'answers'},
                                                                  {'check': 'booted', 'target': '', 'ok': True, 'detail': ''}]),
             'checks': {'agent': 'require', 'ports': [443], 'command': '', 'rto_seconds': 600,
                        'source': {'rto_minutes': 'cluster', 'agent': 'tag:web', 'ports': 'tag:web', 'command': 'default'}},
             'history': [{'id': 't2', 'started_at': '2026-10-28T16:00:00', 'completed_at': '2026-10-28T16:05:00', 'status': 'passed',
                          'backup_time': '2026-10-28T02:00:00', 'duration_seconds': 300, 'measured_seconds': 245.0, 'rto_met': True,
                          'checks': [], 'source': 'schedule', 'cause': ''},
                         {'id': 't0', 'started_at': '2026-10-21T16:00:00', 'completed_at': '2026-10-21T16:09:00', 'status': 'failed',
                          'backup_time': '2026-10-21T02:00:00', 'duration_seconds': 540, 'measured_seconds': None, 'rto_met': None,
                          'checks': [], 'source': 'manual', 'cause': 'guest agent did not answer'}],
             'backups': [{'volid': 'pbs:backup/vm/100/2026-10-30T02:00:00Z', 'ctime': FIXED - 25200, 'storage': 'pbs'}]}


# every state of the spec from the field that decides it, plus the two classic ones beside them
def _states_fixture():
    rows = [
        _rt_row(201, 'passed01', 'ok', last_success_at='2026-10-29T03:00:00', last_success_age_days=1.2,
                tested_backup_at='2026-10-29T02:00:00', tested_backup_age_hours=31.0, measured_seconds=200.0, rto_seconds=600,
                rto_state='met', last_result='passed', last_test_at='2026-10-29T03:00:00'),
        _rt_row(202, 'failed01', 'failing', last_result='failed', last_failure_at='2026-10-29T04:00:00',
                last_failure_cause='boot timeout', last_test_at='2026-10-29T04:00:00'),
        _rt_row(203, 'running01', 'never'),
        _rt_row(204, 'never01', 'never'),
        _rt_row(205, 'nobackup01', 'never', rpo_state='no_backup', backup_count=0, newest_backup_at=None, newest_backup_age_hours=None),
        _rt_row(206, 'partial01', 'ok', last_success_at='2026-10-29T03:00:00', last_success_age_days=1.2, last_result='passed',
                last_test_at='2026-10-29T03:00:00'),
        _rt_row(207, 'stale01', 'stale', last_success_at='2026-09-01T03:00:00', last_success_age_days=59.2, last_result='passed'),
        _rt_row(208, 'slow01', 'rto_missed', last_success_at='2026-10-29T03:00:00', last_success_age_days=1.2,
                measured_seconds=900.0, rto_seconds=600, rto_state='missed', last_result='passed'),
        _rt_row(209, 'unread01', 'ok', last_success_at='2026-10-29T03:00:00', last_success_age_days=1.2, rpo_state='unknown',
                newest_backup_at=None, newest_backup_age_hours=None, backup_count=0),
    ]
    report = dict(RT_REPORT, guests=rows, summary={'ok': 3, 'stale': 1, 'failing': 1, 'never': 3, 'rto_missed': 1, 'total': 9,
                                                   'rpo_breached': 0, 'no_backup': 1})
    proven = {201, 209}
    guests = [dict(r, critical=r['vmid'] == 202, agent_ok=r['vmid'] in proven, app_ok=r['vmid'] in proven,
                   proof='proven' if r['vmid'] in proven else 'not_proven',
                   missing=[] if r['vmid'] in proven else (['application_check'] if r['vmid'] in (206, 208) else ['restore_test', 'agent_check', 'application_check']),
                   gaps=[], confirmation=None) for r in rows]
    assurance = dict(RT_ASSURANCE, guests=guests, gaps=[], gap_counts={},
                     coverage={'critical': {'total': 1, 'proven': 0, 'not_proven': 1, 'percent': 0.0},
                               'all': {'total': 9, 'proven': 2, 'not_proven': 7, 'percent': 22.2}})
    active = {'tid-1': {'id': 'tid-1', 'cluster_id': 'c1', 'vmid': 203, 'vm_name': 'running01', 'status': 'running',
                        'phase': 'booting', 'source': 'manual', 'started_at': '2026-10-30T08:58:00'}}
    return {('GET', '/api/clusters/c1/recovery-report'): (200, report),
            ('GET', '/api/clusters/c1/recovery-assurance'): (200, assurance),
            ('GET', '/api/clusters/c1/backup-verify/active'): (200, active)}


EXPECT_STATUS = {201: 'passed', 202: 'failed', 203: 'running', 204: 'never', 205: 'missing', 206: 'incomplete',
                 207: 'stale', 208: 'rto_missed', 209: 'passed'}


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

    def _open(extra=None, layout=LAYOUT, theme='', viewport=(1600, 1000), **kw):
        server = _GuardServer(bundle=BUNDLE, layout=layout, extra=_reads(extra), **kw)
        app = _GuardApp(browser, server, corp_theme=theme, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _tab(app):
    """The Restore tests sub tab of Testi in the navigation of Corporate Redesigned."""
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip [data-rtest-tab]').first.click()
    _need(page, '[data-cr-rt]', 'the Restore tests sub tab is the page of Corporate Redesigned')
    _need(page, '[data-cr-rt] [data-rtest-row]', 'the guest table is filled')
    page.wait_for_timeout(300)
    return page


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f'rt-{name}.png'), full_page=True)


def _statuses(page):
    """vmid -> the state its row is listed under, in the order of the rows."""
    return {int(k): v for k, v in page.evaluate("""() => ([...document.querySelectorAll('[data-cr-table="rt-guests"] tbody tr')]
        .filter(tr => tr.querySelector('[data-rtest-row]'))
        .map(tr => [Number(tr.querySelector('[data-rtest-row]').dataset.rtestRow),
                    tr.querySelector('[data-cr-rt-status]').dataset.crRtStatus]))""")}


def _tile(page, key):
    return page.locator(f'[data-cr-stat="rt-{key}"] .cr-stat-value').inner_text().strip()


def _body(app, path):
    return [b for b in app.server.bodies.get(path, []) if b][-1]


def _wait(page, pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        page.wait_for_timeout(100)
    return pred()


def _no_errors(app):
    assert [e for e in app.errors if 'not mocked' not in e] == [], app.errors


# --- the parts and the states ------------------------------------------------------------------

def test_runtime_the_page_has_the_five_parts_and_keeps_the_sub_tab_strip(open_app):
    # the server stores no counts with a run (restore_tests.py): they are added up from its results
    status = copy.deepcopy(RT_STATUS)
    del status['last_run']['counts']
    app = open_app({('GET', '/api/pbs/verify-schedule/status'): (200, status)})
    page = _tab(app)
    assert page.locator('[data-cr-nc-kv="rt-run"] [data-cr-nc-k="counts"] dd').inner_text().strip() == \
        '2 picked, 1 passed, 1 failed, 1 skipped'
    heads = page.locator('[data-cr-rt] h2.cr-rt-h').all_inner_texts()
    assert [h.strip().lower() for h in heads] == ['recovery overview', 'schedule and test configuration',
                                                   'guest selection and test policies', 'execution and progress',
                                                   'results and evidence']
    # the strip of the Datastore tab stays (the guest page links to it by data-rtest-tab)
    assert page.locator('.corp-tab-strip button.active[data-rtest-tab]').count() == 1
    for sec in ('rt-schedule', 'rt-defaults', 'rt-critical', 'rt-rules', 'rt-exec', 'rt-guests', 'rt-gaps',
                'rt-confirmations', 'rt-evidence-doc'):
        assert page.locator(f'[data-cr-nc-sec="{sec}"]').count() == 1, sec
    # the classic panel is not drawn beside it
    assert page.locator('.bg-proxmox-card[data-rtest-panel]').count() == 0
    _shot(page, 'overview')
    _no_errors(app)


def test_runtime_every_guest_is_listed_under_the_state_its_fields_decide(open_app):
    app = open_app(_states_fixture())
    page = _tab(app)
    page.wait_for_function('() => document.querySelectorAll("[data-cr-table=rt-guests] [data-rtest-row]").length === 9', timeout=8000)
    assert _statuses(page) == EXPECT_STATUS
    # the tiles add up: one state per guest
    assert [_tile(page, k) for k in ('passed', 'failed', 'running', 'never', 'missing', 'incomplete')] == ['2', '1', '1', '1', '1', '1']
    # the running one comes from the live tests and says its phase
    live = page.locator('[data-cr-table="rt-live"] tbody tr', has=page.locator('[data-cr-rt-live="203"]'))
    assert 'Booting' in live.inner_text()
    # unread storages are not a missing backup
    assert page.locator('[data-rtest-row="209"]').count() == 1
    row209 = page.locator('[data-cr-table="rt-guests"] tbody tr', has=page.locator('[data-rtest-row="209"]'))
    assert row209.locator('[data-cr-rt-backup="unknown"]').inner_text().strip() == 'not reported'
    row205 = page.locator('[data-cr-table="rt-guests"] tbody tr', has=page.locator('[data-rtest-row="205"]'))
    assert row205.locator('[data-cr-rt-backup="no_backup"]').inner_text().strip() == 'Missing backup'
    # evidence: proven, incomplete with what is missing, none without a passed test
    row206 = page.locator('[data-cr-table="rt-guests"] tbody tr', has=page.locator('[data-rtest-row="206"]'))
    assert row206.locator('[data-cr-rt-evidence="incomplete"]').inner_text().strip().startswith('Evidence incomplete')
    assert 'application check' in row206.inner_text()
    _shot(page, 'states')
    _no_errors(app)


def test_runtime_a_tile_filters_the_table_and_a_second_click_lifts_it(open_app):
    app = open_app(_states_fixture())
    page = _tab(app)
    page.locator('[data-cr-stat="rt-failed"]').click()
    page.wait_for_timeout(300)
    assert list(_statuses(page)) == [202]
    assert page.locator('[data-cr-stat="rt-failed"]').get_attribute('aria-pressed') == 'true'
    # the filter shows in the toolbar of the table too
    assert page.locator('[data-cr-rt-chips] button.active').inner_text().startswith('Failed')
    page.locator('[data-cr-stat="rt-failed"]').click()
    page.wait_for_timeout(300)
    assert len(_statuses(page)) == 9
    page.locator('[data-cr-rt-chips] button[data-rtest-tile="attention"]').click()
    page.wait_for_timeout(300)
    assert sorted(_statuses(page)) == [202, 203, 204, 205, 206, 207, 208]
    page.locator('[data-cr-rt-chips] button[data-rtest-tile="critical"]').click()
    page.wait_for_timeout(300)
    assert list(_statuses(page)) == [202]
    _no_errors(app)


def test_runtime_without_the_assurance_the_evidence_is_not_reported(open_app):
    over = _states_fixture()
    over[('GET', '/api/clusters/c1/recovery-assurance')] = (500, {'error': 'assurance read failed'})
    app = open_app(over)
    page = _tab(app)
    _need(page, '[data-rasr-error]', 'the failed assurance read is said')
    assert 'assurance read failed' in page.locator('[data-rasr-error]').inner_text()
    assert _tile(page, 'incomplete') == 'not reported'
    assert _tile(page, 'cov-critical') == 'not reported'
    row206 = page.locator('[data-cr-table="rt-guests"] tbody tr', has=page.locator('[data-rtest-row="206"]'))
    assert row206.locator('[data-cr-rt-evidence]').inner_text().strip() == 'not reported'
    # without the assurance, a passed guest stays passed: nothing turns into incomplete or proven
    assert _statuses(page)[206] == 'passed'
    # critical guests still come from the tags of the settings
    assert page.locator('[data-cr-rt-chips] button[data-rtest-tile="critical"] .cr-seg-n').inner_text() == '0'
    _no_errors(app)


def test_runtime_without_vm_backup_the_live_tests_are_not_reported_as_none(open_app):
    over = _states_fixture()
    over[('GET', '/api/clusters/c1/backup-verify/active')] = (403, {'error': 'Permission denied'})
    app = open_app(over)
    page = _tab(app)
    _need(page, '[data-cr-nc-state="info"][data-cr-nc-for="rt-live"]', 'a 403 of the live tests is said')
    assert 'vm.backup' in page.locator('[data-cr-nc-for="rt-live"]').inner_text()
    assert page.locator('[data-cr-stat="rt-running"] .cr-stat-sub').inner_text() == 'manual tests not reported'
    assert _statuses(page)[203] == 'never'
    _no_errors(app)


def test_runtime_the_weekly_run_in_progress_shows_the_guest_in_flight_and_the_queue(open_app):
    status = copy.deepcopy(RT_STATUS)
    status['running'] = True
    status['last_run'].update(state='running', finished_at=None, counts=None,
                              picked=[{'cluster_id': 'c2', 'vmid': 900, 'volid': 'x:900'},
                                      {'cluster_id': 'c1', 'vmid': 101, 'volid': 'pbs:backup/vm/101/a'},
                                      {'cluster_id': 'c1', 'vmid': 100, 'volid': 'pbs:backup/vm/100/a'},
                                      {'cluster_id': 'c1', 'vmid': 102, 'volid': 'pbs:backup/vm/102/a'}],
                              results=[{'cluster_id': 'c2', 'vmid': 900, 'volid': 'x:900', 'status': 'passed', 'name': 'other'},
                                       {'cluster_id': 'c1', 'vmid': 101, 'volid': 'pbs:backup/vm/101/a', 'name': 'db01',
                                        'status': 'failed', 'cause': 'port 5432: nothing listens'}])
    app = open_app({('GET', '/api/pbs/verify-schedule/status'): (200, status)})
    page = _tab(app)
    _need(page, '[data-cr-rt-exec="running"]', 'the run section says a run is going on')
    assert page.locator('[data-cr-rt-progress]').get_attribute('data-cr-rt-progress') == '1/3'
    states = page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[data-cr-table="rt-plan"] [data-rtest-result]')]
        .map(e => [e.dataset.rtestResult, e.dataset.state]))""")
    assert states == {'101': 'failed', '100': 'running', '102': 'queued'}
    assert _statuses(page)[100] == 'running'
    # the runs are read again while one is going on (every 10 s), never per guest
    before = len([c for c in app.server.calls if c == ('GET', '/api/pbs/verify-schedule/status')])
    page.wait_for_timeout(10800)
    after = len([c for c in app.server.calls if c == ('GET', '/api/pbs/verify-schedule/status')])
    assert after == before + 1
    assert not [c for c in app.server.calls if re.fullmatch(r'/api/clusters/c1/recovery-report/\d+', c[1])]
    _shot(page, 'running')
    _no_errors(app)


# --- the writes, as the classic panel sends them -------------------------------------------------

def _classic_defaults_body(app):
    """The body the classic panel sends for the same edits (Corporate classic, same fake)."""
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.locator('[data-rtest-tab]').first.click()
    page.locator('[data-rtest-field="rto"]').first.wait_for(timeout=8000)
    page.locator('[data-rtest-field="rto"]').fill('15')
    page.locator('[data-rtest-field="isolation"]').select_option('bridge')
    page.locator('[data-rtest-field="bridge"]').fill('vmbr99')
    page.locator('[data-rtest-field="ports"]').fill('22, 443')
    page.locator('[data-rtest-save]').click()
    assert _wait(page, lambda: ('PUT', '/api/clusters/c1/recovery-settings') in app.server.calls)
    return _body(app, '/api/clusters/c1/recovery-settings')


def test_runtime_the_defaults_are_edited_in_place_and_save_the_classic_body(open_app):
    classic = _classic_defaults_body(open_app(layout='corporate'))
    app = open_app()
    page = _tab(app)
    sec = page.locator('[data-cr-nc-sec="rt-defaults"]')
    sec.locator('[data-cr-rt-edit="defaults"]').click()
    assert sec.get_attribute('data-cr-nc-editing') == ''
    sec.locator('[data-rtest-field="rto"]').fill('15')
    sec.locator('[data-rtest-field="isolation"]').select_option('bridge')
    sec.locator('[data-rtest-field="bridge"]').fill('vmbr99')
    sec.locator('[data-rtest-field="ports"]').fill('22, 443')
    # before Save: what differs from the stored value, and nothing is sent yet
    changes = sec.locator('[data-cr-nc-changes="rt-defaults"] li').evaluate_all('ls => ls.map(l => l.dataset.crNcChange)')
    assert changes == ['rto_minutes', 'isolation', 'test_bridge', 'ports']
    assert ('PUT', '/api/clusters/c1/recovery-settings') not in app.server.calls
    # Cancel drops the edits
    sec.locator('[data-cr-nc-cancel="rt-defaults"]').click()
    assert sec.locator('[data-cr-nc-k="rto"] dd').inner_text().strip() == '10 min'
    sec.locator('[data-cr-rt-edit="defaults"]').click()
    sec.locator('[data-rtest-field="rto"]').fill('15')
    sec.locator('[data-rtest-field="isolation"]').select_option('bridge')
    sec.locator('[data-rtest-field="bridge"]').fill('vmbr99')
    sec.locator('[data-rtest-field="ports"]').fill('22, 443')
    sec.locator('[data-cr-nc-save="rt-defaults"]').click()
    assert _wait(page, lambda: ('PUT', '/api/clusters/c1/recovery-settings') in app.server.calls)
    assert _body(app, '/api/clusters/c1/recovery-settings') == classic
    assert classic == {'rto_minutes': 15, 'isolation': 'bridge', 'test_bridge': 'vmbr99', 'test_storage': None,
                       'boot_timeout': 180, 'agent': 'auto', 'ports': [22, 443], 'command': None}
    _no_errors(app)


def test_runtime_critical_tags_rules_and_confirmations_send_the_classic_requests(open_app):
    app = open_app()
    page = _tab(app)
    calls = app.server.calls
    # critical tags: edit bar, then the body of RecoveryAssurance.saveTags
    crit = page.locator('[data-cr-nc-sec="rt-critical"]')
    crit.locator('[data-cr-rt-edit="critical"]').click()
    crit.locator('[data-rasr-tags]').fill('critical, gold ,')
    assert crit.locator('[data-cr-nc-change="tags"]').count() == 1
    crit.locator('[data-cr-nc-save="rt-critical"]').click()
    assert _wait(page, lambda: ('PUT', '/api/clusters/c1/recovery-settings') in app.server.calls)
    assert _body(app, '/api/clusters/c1/recovery-settings') == {'critical_tags': ['critical', 'gold']}
    # a rule: the body of the classic addRule
    rules = page.locator('[data-cr-nc-sec="rt-rules"]')
    rules.locator('[data-cr-rt-add-rule]').click()
    rules.locator('[data-rtest-rule-field="scope"]').select_option('tag')
    rules.locator('[data-rtest-rule-field="key"]').fill(' db ')
    rules.locator('[data-rtest-rule-field="rto"]').fill('20')
    rules.locator('[data-rtest-rule-field="ports"]').fill('5432')
    rules.locator('[data-rtest-rule-field="command"]').fill('pg_isready')
    rules.locator('[data-rtest-rule-add]').click()
    assert _wait(page, lambda: ('PUT', '/api/clusters/c1/recovery-settings/rules') in app.server.calls)
    assert _body(app, '/api/clusters/c1/recovery-settings/rules') == {'scope': 'tag', 'key': 'db', 'rto_minutes': 20,
                                                                      'ports': [5432], 'command': 'pg_isready'}
    # removing a rule: the classic DELETE, in the danger style
    remove = rules.locator('[data-rtest-rule-remove="guest:101"]')
    assert 'cr-btn-danger' in remove.get_attribute('class')
    remove.click()
    assert _wait(page, lambda: ('DELETE', '/api/clusters/c1/recovery-settings/rules/guest/101') in calls)
    # a manual confirmation from the gap list: the body of saveConfirm
    page.locator('[data-cr-table="rt-gaps"] [data-rasr-confirm-open="101"]').first.click()
    dlg = page.locator('[data-cr-upd-dialog="rt-confirm"]')
    dlg.locator('[data-rasr-field="text"]').fill('Restored by hand on 29.10.')
    dlg.locator('[data-rasr-field="days"]').fill('30')
    dlg.locator('[data-rasr-save-confirm]').click()
    assert _wait(page, lambda: ('POST', '/api/clusters/c1/recovery-confirmations') in app.server.calls)
    assert _body(app, '/api/clusters/c1/recovery-confirmations') == {'vmid': 101, 'text': 'Restored by hand on 29.10.', 'expires_days': 30}
    page.locator('[data-cr-upd-dialog="rt-confirm"]').wait_for(state='detached', timeout=5000)
    # withdrawing one: the classic DELETE
    page.locator('[data-cr-table="rt-confirmations"] [data-rasr-withdraw="102"]').click()
    assert _wait(page, lambda: ('DELETE', '/api/clusters/c1/recovery-confirmations/0123456789abcdef') in calls)
    _no_errors(app)


def test_runtime_exports_verify_and_the_schedule_dialog_are_the_classic_ones(open_app, tmp_path):
    app = open_app()
    page = _tab(app)
    assert page.locator('[data-cr-rt] [data-rtest-csv]').get_attribute('href').endswith('/api/clusters/c1/recovery-report?days=30&format=csv')
    page.locator('[data-rtest-days]').select_option('14')
    assert _wait(page, lambda: any(u.endswith('/recovery-report?days=14') for u in app.server.urls))
    assert _wait(page, lambda: any(u.endswith('/recovery-assurance?days=14') for u in app.server.urls))
    hrefs = {k: page.locator(f'[data-rasr-export="{k}"]').get_attribute('href') for k in ('json', 'csv')}
    assert hrefs['json'].endswith('/api/clusters/c1/recovery-evidence?days=14&format=json')
    assert hrefs['csv'].endswith('/api/clusters/c1/recovery-evidence?days=14&format=csv')
    doc = tmp_path / 'evidence.json'
    doc.write_text(json.dumps({'kind': 'evidence', 'signature': 'abc'}))
    page.locator('[data-rasr-verify]').set_input_files(str(doc))
    _need(page, '[data-rasr-verdict="ok"]', 'the verdict of the verify route is shown')
    assert _body(app, '/api/recovery-evidence/verify') == {'kind': 'evidence', 'signature': 'abc'}
    # the weekly run is edited in the classic dialog with its consent
    page.locator('[data-cr-nc-sec="rt-schedule"] [data-rtest-edit-schedule]').click()
    _need(page, '[data-rtest-enabled]', 'the classic schedule dialog opens')
    assert ('GET', '/api/pbs/verify-schedule') in app.server.calls
    page.locator('[data-rtest-max-gb]').fill('64')
    page.locator('button', has_text=re.compile(r'^\s*Save\s*$')).last.click()
    assert _wait(page, lambda: ('PUT', '/api/pbs/verify-schedule') in app.server.calls)
    assert _body(app, '/api/pbs/verify-schedule')['max_backup_gb'] == 64
    # Refresh reads the report with refresh=1, as classic does
    page.locator('[data-cr-rt] [data-rtest-refresh]').click()
    assert _wait(page, lambda: any('refresh=1' in u and '/recovery-report?' in u for u in app.server.urls))
    _no_errors(app)


def test_runtime_a_guest_opens_on_its_own_with_one_read(open_app):
    app = open_app()
    page = _tab(app)
    assert not [c for c in app.server.calls if c[1] == '/api/clusters/c1/recovery-report/100']
    page.locator('[data-cr-table="rt-guests"] [data-rtest-row="100"]').click()
    _need(page, '[data-cr-sidepanel="rt-guest"] [data-rtest-history="t2"], [data-cr-sidepanel="rt-guest"] [data-cr-table="rt-history"] tbody tr',
          'the side panel shows the history of the guest')
    panel = page.locator('[data-cr-sidepanel="rt-guest"]')
    assert panel.locator('[data-rtest-check="agent"]').count() == 1
    assert panel.locator('[data-cr-table="rt-history"] tbody tr').count() == 2
    assert 'pbs:backup/vm/100' in panel.locator('[data-cr-rt-backups]').inner_text()
    _shot(page, 'guest')
    page.keyboard.press('Escape')
    page.locator('[data-cr-sidepanel="rt-guest"]').wait_for(state='detached', timeout=5000)
    page.locator('[data-cr-table="rt-guests"] [data-rtest-row="100"]').click()
    page.locator('[data-cr-sidepanel="rt-guest"]').wait_for(timeout=5000)
    assert len([c for c in app.server.calls if c[1] == '/api/clusters/c1/recovery-report/100']) == 1
    _no_errors(app)


# --- standby, language, scale, layout ------------------------------------------------------------

def test_runtime_a_standby_reads_and_writes_nothing(open_app):
    app = open_app(role='standby')
    page = _tab(app)
    _need(page, '[data-cr-nc-for="rt-standby"]', 'the standby says it is read only')
    assert page.locator('[data-cr-rt-edit="defaults"]').is_disabled()
    assert page.locator('[data-cr-rt-edit="critical"]').is_disabled()
    assert page.locator('[data-cr-rt-add-rule]').is_disabled()
    assert page.locator('[data-rtest-edit-schedule]').is_disabled()
    assert page.locator('[data-rtest-rule-remove]').count() == 0
    assert page.locator('[data-rasr-confirm-open]').count() == 0
    assert page.locator('[data-rasr-withdraw]').count() == 0
    _no_errors(app)


def test_runtime_in_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip [data-rtest-tab]').first.click()
    _need(page, '[data-cr-rt] [data-rtest-row]', 'the guest table is filled')
    heads = page.locator('[data-cr-rt] h2.cr-rt-h').all_inner_texts()
    assert [h.strip().lower() for h in heads][0] == 'wiederherstellung im überblick'
    assert page.locator('[data-cr-stat="rt-missing"] .cr-stat-label').inner_text().strip().lower() == 'backup fehlt'
    _no_errors(app)


def test_runtime_10000_guests_one_read_and_a_virtual_table(open_app):
    rows = [_rt_row(1000 + i, f'g{i:05d}', ['ok', 'failing', 'never', 'stale'][i % 4], node=f'pve{i % 200}',
                    last_success_age_days=1.0 if i % 4 in (0, 3) else None) for i in range(10000)]
    report = dict(RT_REPORT, guests=rows)
    guests = [dict(r, critical=False, proof='proven' if r['state'] == 'ok' else 'not_proven', missing=[], gaps=[], confirmation=None)
              for r in rows]
    over = {('GET', '/api/clusters/c1/recovery-report'): (200, report),
            ('GET', '/api/clusters/c1/recovery-assurance'): (200, dict(RT_ASSURANCE, guests=guests, gaps=[], gap_counts={}))}
    app = open_app(over)
    page = app.page
    t0 = time.time()
    _tab(app)
    page.wait_for_function('() => document.querySelector("[data-cr-stat=rt-failed] .cr-stat-value")?.textContent === "2500"', timeout=15000)
    took = time.time() - t0
    assert took < 12, took
    assert page.locator('[data-cr-table="rt-guests"] tbody tr').count() < 120
    page.locator('[data-cr-stat="rt-never"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-table=rt-guests] .cr-table-count")?.textContent.startsWith("2500")', timeout=8000)
    assert not [c for c in app.server.calls if re.fullmatch(r'/api/clusters/c1/recovery-report/\d+', c[1])]
    assert len([c for c in app.server.calls if c[1] == '/api/clusters/c1/recovery-report']) == 1
    _no_errors(app)


@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_no_sideways_scroll(open_app, width):
    app = open_app(_states_fixture(), viewport=(width, 900))
    page = _tab(app)
    over = page.evaluate("""() => { const el = document.querySelector('[data-cr-rt]');
        return { page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                 view: el.scrollWidth - el.clientWidth }; }""")
    assert over['page'] <= 0 and over['view'] <= 0, over
    _shot(page, f'w{width}')
    _no_errors(app)


# --- source ----------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_keys_are_in_every_language_once_and_before_the_banners():
    tr = _read('web', 'src', 'translations.js')
    src = _read('web', 'src', 'cr_recovery.js')
    used = set(re.findall(r"'(crRt[A-Za-z]+)'", src))
    assert used
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        found = set(re.findall(r'^\s*(crRt[A-Za-z]+):', block, re.M))
        # every language carries them since the translation stage, once and before the banners
        assert found == used, (lang, sorted(used ^ found))
        for key in used:
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)
        assert block.index('crRtAssurFailed:') < block.index('haNoLeader:'), lang
        for v in re.findall(r'^\s*crRt[A-Za-z]+: (".*"),$', block, re.M):
            assert not any(d in v for d in DASHES), v
    assert not any(d in src for d in DASHES)


def test_the_variant_is_gated_and_in_the_build():
    storage = _read('web', 'src', 'storage.js')
    assert ") : activeTab === 'recovery' && isCorpRedesigned ? (" in storage
    assert storage.index('<CrRestoreTests ') < storage.index('<RestoreTestsPanel clusterId={clusterId} addToast={addToast} />')
    assert 'cr_recovery.js' in _read('web', 'Dev', 'build.sh')
    assert 'function CrRestoreTests(' in _read('web', 'index.html')
