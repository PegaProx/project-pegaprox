"""The restore tests in the browser: the tab of the datastore view, the cloud backups page, the
schedule dialog and the restore_test_age alert rule.

Source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern, Corporate and
Cloud, as an active instance and as a standby, in English and German. They skip where
Playwright is not installed. The routes behind them are tested in tests/test_recovery_report.py.
LW Oct 2026
"""
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
DASHES = (chr(0x2014), chr(0x2013))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s) + len(end)]


def _blocks():
    ui, storage = _read('web', 'src', 'ui.js'), _read('web', 'src', 'storage.js')
    cloud, dash = _read('web', 'src', 'cloud.js'), _read('web', 'src', 'dashboard.js')
    return [
        _between(ui, '// LW Oct 2026 - the restore tests of a cluster', 'window.PegaProxRestoreTestsPanel = RestoreTestsPanel; } catch (_) {}'),
        _between(ui, "<div className=\"opacity-70 mb-1\">{t('rtestMaxAge')}</div>", "{t('rtestIsoNote')}</p>"),
        _between(storage, '{/* LW Oct 2026 - restore tests: the weekly run', '</button>'),
        _between(storage, "onClick={() => setActiveTab('recovery')} data-rtest-tab", '</button>'),
        _between(storage, ") : activeTab === 'recovery' ? (", '<RestoreTestsPanel clusterId={clusterId} addToast={addToast} />'),
        _between(cloud, '// LW Oct 2026 - the restore tests of the cluster under', 'function CloudBackups('),
        _between(dash, "{/* LW Oct 2026 - days without a restore test that passed", "{alertMetricSel !== 'rolling_update' && ("),
        _between(dash, "if (alert.metric === 'restore_test_age') {", 'return `${alert.metric?.toUpperCase()}'),
    ]


def _keys():
    used = set()
    for block in _blocks():
        used |= set(re.findall(r"t\('((?:rtest|restoreTestAge)[A-Za-z]*)'\)", block))
    used |= set(re.findall(r"t\('((?:rtest|restoreTestAge)[A-Za-z]*)'\)", _read('web', 'src', 'dashboard.js')))
    return sorted(used)


# --- source --------------------------------------------------------------------------------

def test_every_new_string_is_in_every_language_once():
    tr = _read('web', 'src', 'translations.js')
    keys = _keys()
    assert len(keys) == 85
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    assert [s[0] for s in starts] == LANGS
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        for key in keys:
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)


def test_no_key_is_left_unused():
    tr = _read('web', 'src', 'translations.js')
    defined = set(re.findall(r'^\s*((?:rtest|restoreTestAge)[A-Za-z]*):', tr, re.M))
    assert defined == set(_keys()), (sorted(defined - set(_keys())), sorted(set(_keys()) - defined))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key in _keys():
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9, key
        wanted = set(re.findall(r'\{(\w+)\}', values[LANGS.index('en')]))
        for v in values:
            assert set(re.findall(r'\{(\w+)\}', v)) == wanted, (key, v)


def test_the_keys_sit_with_the_backup_sla_and_the_alert_rules():
    tr = _read('web', 'src', 'translations.js')
    for block in re.split(r'^            [a-z]{2}: \{$', tr, flags=re.M)[1:]:
        lines = [ln.strip().split(':', 1)[0] for ln in block.splitlines()]
        assert lines[lines.index('backupSlaDesc') + 1] == 'rtestTab'
        assert lines[lines.index('replicationRpoSummaryAuto') + 1] == 'restoreTestAgeTitle'
    assert "{ code: 'de', flag: '🇦🇹'" in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_what_this_change_added():
    for block in _blocks():
        assert not any(d in block for d in DASHES), block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in _keys():
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert not any(d in v for d in DASHES), (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    used = set()
    for block in _blocks():
        used |= set(re.findall(r'Icons\.([A-Za-z]+)', block)) | set(re.findall(r'icon[:=] ?["\']([A-Z][A-Za-z]+)["\']', block))
    assert used and used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    from test_ha_ui import _classes
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _blocks():
        names |= _classes(block)
    missing = sorted(n for n in names - {'field'} if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_existing_metric_list_keeps_its_shape():
    """Three other alert tests read the list literally; the new metric is pushed after it."""
    dash = _read('web', 'src', 'dashboard.js')
    assert "'zfs_health', 'clock_drift', 'restart_loop', 'qdevice'];\n" in dash
    assert "EVENT_ALERT_METRICS.push('restore_test_age');" in dash


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function RestoreTestsPanel(', 'function CloudRestoreTests(', '/recovery-report',
                   '/recovery-settings/rules', 'data-rtest-tab', 'React.createElement("option",{value:"restore_test_age"}',
                   'data-event-fields":"restore_test_age"', 'rtestCloudNotRecent', 'data-rtest-max-age'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _row(vmid, name, state, **kw):
    r = {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'tags': [], 'state': state,
         'last_test_at': None, 'last_result': None, 'last_success_at': None, 'last_success_age_days': None,
         'tested_backup_at': None, 'tested_backup_age_hours': None, 'measured_seconds': None, 'rto_seconds': None,
         'rto_state': 'none', 'newest_backup_at': '2026-10-10T02:00:00', 'newest_backup_age_hours': 3.0,
         'backup_count': 4, 'sla_hours': 24, 'rpo_state': 'ok', 'last_failure_at': None, 'last_failure_cause': None,
         'cluster_id': 'c1', 'cluster_name': 'Testi'}
    r.update(kw)
    return r


ROWS = [
    _row(101, 'db01', 'failing', last_result='failed', last_failure_at='2026-10-09T04:10:00',
         last_failure_cause='port 5432: nothing listens', rpo_state='breached', newest_backup_age_hours=30.0),
    _row(102, 'mail01', 'never'),
    _row(100, 'web01', 'ok', last_success_at='2026-10-08T16:05:00', last_success_age_days=1.5,
         tested_backup_at='2026-10-08T02:00:00', tested_backup_age_hours=50.0, measured_seconds=245.0,
         rto_seconds=600, rto_state='met', last_result='passed'),
]
SUMMARY = {'ok': 1, 'stale': 0, 'failing': 1, 'never': 1, 'rto_missed': 0, 'total': 3, 'rpo_breached': 1, 'no_backup': 0}
REPORT = {'cluster_id': 'c1', 'cluster_name': 'Testi', 'backups_read_at': '2026-10-10T05:00:00', 'backups_state': 'partial',
          'sla_hours': 24, 'stale_days': 30, 'summary': SUMMARY, 'guests': ROWS,
          'settings': {'rto_minutes': 10, 'isolation': 'link_down', 'test_bridge': '', 'test_storage': '',
                       'boot_timeout': 180, 'agent': 'auto', 'ports': [], 'command': ''}}
SETTINGS = {'cluster': {'rto_minutes': 10, 'agent': 'auto', 'ports': [], 'command': '', 'isolation': 'link_down',
                        'test_bridge': '', 'test_storage': '', 'boot_timeout': 180},
            'guests': [{'scope': 'guest', 'scope_key': '101', 'rto_minutes': 5, 'agent': None, 'ports': [5432],
                        'command': 'pg_isready', 'updated_at': '2026-10-09T10:00:00', 'updated_by': 'admin'}],
            'tags': [], 'can_edit': True, 'limits': {}}
NEXT = '2026-10-11T04:00:00'
STATUS = {'policy': {'enabled': True, 'weekly_count': 5, 'day': 'sun', 'hour': 4, 'scope': 'latest_per_vm', 'max_age_days': 30},
          'next_run': NEXT, 'running': False, 'timezone': 'Europe/Vienna',
          'last_run': {'slot': '2026-10-04T04:00:00', 'state': 'done', 'started_at': time.time() - 7 * 86400,
                       'finished_at': time.time() - 7 * 86400 + 1800, 'reason': '',
                       'picked': [{'cluster_id': 'c1', 'vmid': 101}, {'cluster_id': 'c1', 'vmid': 100}],
                       'results': [{'cluster_id': 'c1', 'vmid': 101, 'name': 'db01', 'status': 'failed',
                                    'cause': 'port 5432: nothing listens', 'task_id': 't1'},
                                   {'cluster_id': 'c1', 'vmid': 100, 'name': 'web01', 'status': 'passed', 'cause': '',
                                    'task_id': 't2'}],
                       'counts': {'picked': 2, 'passed': 1, 'failed': 1, 'skipped': 0}}}
GUEST = {'guest': dict(ROWS[2], last_checks=[{'check': 'agent', 'target': '', 'ok': True, 'detail': 'answers'},
                                            {'check': 'port', 'target': '443', 'ok': True, 'detail': 'listening'}]),
         'checks': {'agent': 'auto', 'ports': [443], 'command': '', 'rto_seconds': 600,
                    'source': {'rto_minutes': 'cluster', 'agent': 'default', 'ports': 'tag:web', 'command': 'default'}},
         'history': [{'id': 't2', 'started_at': '2026-10-08T04:00:00', 'completed_at': '2026-10-08T04:06:00',
                      'status': 'passed', 'backup_time': '2026-10-08T02:00:00', 'duration_seconds': 300,
                      'measured_seconds': 245.0, 'rto_met': True, 'checks': [], 'source': 'schedule', 'cause': ''}],
         'backups': []}
PBS = {'storage': 'backupsrv', 'type': 'pbs', 'content': 'backup', 'shared': 1, 'total': 500 * 2 ** 30,
       'used': 50 * 2 ** 30, 'avail': 450 * 2 ** 30, 'active': 1, 'enabled': 1, 'used_fraction': 0.1}
DATASTORES = {'shared': [PBS], 'local': {'pve1': []}, 'nodes': ['pve1']}


def _reads(over=None):
    extra = dict(SSE_TOKEN)
    extra.update({
        ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
        ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
        ('GET', '/api/clusters/c1/recovery-report'): (200, REPORT),
        ('GET', '/api/clusters/c1/recovery-report/100'): (200, GUEST),
        ('GET', '/api/clusters/c1/recovery-settings'): (200, SETTINGS),
        ('GET', '/api/pbs/verify-schedule/status'): (200, STATUS),
        ('GET', '/api/pbs/verify-schedule'): (200, STATUS['policy']),
        ('PUT', '/api/pbs/verify-schedule'): (200, STATUS['policy']),
        ('PUT', '/api/clusters/c1/recovery-settings'): (200, {'success': True, 'cluster': SETTINGS['cluster']}),
        ('PUT', '/api/clusters/c1/recovery-settings/rules'): (200, {'success': True, 'rule': None}),
        ('DELETE', '/api/clusters/c1/recovery-settings/rules/guest/101'): (200, {'success': True}),
    })
    extra.update(over or {})
    return extra


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(extra=None, **kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                                        extra=extra if extra is not None else _reads(), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open_tab(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.locator('[data-rtest-tab]').first.click()
    page.locator('[data-rtest-row]').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _body(app, path):
    return [b for b in app.server.bodies.get(path, []) if b][-1]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_report_the_schedule_and_a_guest(open_app, layout):
    app = open_app(layout=layout)
    page = _open_tab(app, layout)
    panel = page.locator('[data-rtest-panel="c1"]')
    assert 'Restore tests' in panel.inner_text()
    rows = page.locator('[data-rtest-row]')
    assert rows.evaluate_all('rs => rs.map(r => [r.dataset.rtestRow, r.dataset.state])') == [
        ['101', 'failing'], ['102', 'never'], ['100', 'ok']]
    failing, ok = rows.nth(0).inner_text(), rows.nth(2).inner_text()
    assert 'Failing' in failing and 'port 5432: nothing listens' in failing and 'never' in failing.lower()
    # under two days in hours, then in days
    assert 'Recoverable' in ok and '36.0 h ago' in ok and '2 d ago' in ok and '4m 5s of 10m 0s' in ok
    assert 'SLA 24 h' in ok
    assert page.locator('[data-rtest-backups-note]').inner_text().startswith('Some backup storages did not answer')
    # the weekly run, on the group's clock
    sched = page.locator('[data-rtest-schedule="on"]')
    assert 'Next run:' in sched.inner_text() and '(Europe/Vienna)' in sched.inner_text()
    assert '2 picked, 1 passed, 1 failed, 0 skipped' in page.locator('[data-rtest-last]').inner_text()
    assert page.locator('[data-rtest-result="101"]').get_attribute('data-state') == 'failed'
    # a tile filters, its chip clears the filter
    page.locator('[data-rtest-tile="never"]').click()
    assert page.locator('[data-rtest-row]').count() == 1
    page.locator('[data-rtest-filter="never"]').click()
    assert page.locator('[data-rtest-row]').count() == 3
    page.locator('[data-rtest-search]').fill('web')
    assert page.locator('[data-rtest-row]').count() == 1
    page.locator('[data-rtest-search]').fill('')
    # nothing of a guest is read before its row is opened, then once
    assert not [u for u in app.server.urls if '/recovery-report/' in u]
    page.locator('[data-rtest-row="100"]').click()
    detail = page.locator('[data-rtest-detail="100"]')
    detail.locator('[data-rtest-history="t2"]').wait_for(timeout=5000)
    text = detail.inner_text()
    assert 'Port 443' in text and 'weekly run' in text and 'RTO 10m 0s' in text
    page.locator('[data-rtest-row="100"]').click()
    page.locator('[data-rtest-row="100"]').click()
    assert len([u for u in app.server.urls if '/recovery-report/100' in u]) == 1
    # the export is the report as CSV, of the period shown
    assert page.locator('[data-rtest-csv]').get_attribute('href').endswith('/api/clusters/c1/recovery-report?days=30&format=csv')
    page.locator('[data-rtest-days]').select_option('60')
    deadline = time.time() + 4
    while time.time() < deadline and not any('days=60' in u for u in app.server.urls):
        page.wait_for_timeout(100)
    assert any('recovery-report?days=60' in u for u in app.server.urls)
    _shot(page, f'rtest_{layout}.png')
    assert not app.errors, app.errors


def test_runtime_an_admin_sets_what_the_tests_do(open_app):
    app = open_app(layout='modern')
    page = _open_tab(app, 'modern')
    settings = page.locator('[data-rtest-settings]')
    assert 'new MAC addresses' in settings.inner_text()
    assert page.locator('[data-rtest-rule="guest:101"]').inner_text().count('pg_isready') == 1
    page.locator('[data-rtest-field="rto"]').fill('15')
    page.locator('[data-rtest-field="isolation"]').select_option('bridge')
    page.locator('[data-rtest-field="bridge"]').fill('vmbr99')
    page.locator('[data-rtest-field="ports"]').fill('22, 443')
    page.locator('[data-rtest-save]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/recovery-settings'))
    body = _body(app, '/api/clusters/c1/recovery-settings')
    assert body == {'rto_minutes': 15, 'isolation': 'bridge', 'test_bridge': 'vmbr99', 'test_storage': None,
                    'boot_timeout': 180, 'agent': 'auto', 'ports': [22, 443], 'command': None}
    # a tag rule
    page.locator('[data-rtest-rule-field="scope"]').select_option('tag')
    page.locator('[data-rtest-rule-field="key"]').fill('db')
    page.locator('[data-rtest-rule-field="ports"]').fill('5432')
    page.locator('[data-rtest-rule-field="command"]').fill('pg_isready')
    page.locator('[data-rtest-rule-add]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/recovery-settings/rules'))
    assert _body(app, '/api/clusters/c1/recovery-settings/rules') == {'scope': 'tag', 'key': 'db', 'ports': [5432],
                                                                      'command': 'pg_isready'}
    page.locator('[data-rtest-rule-remove="guest:101"]').click()
    assert _wait_for_call(app, ('DELETE', '/api/clusters/c1/recovery-settings/rules/guest/101'))
    assert not app.errors, app.errors


def test_runtime_the_schedule_dialog_takes_the_oldest_backup_too(open_app):
    app = open_app(layout='corporate')
    page = _open_tab(app, 'corporate')
    page.locator('[data-rtest-edit-schedule]').click()
    page.locator('[data-rtest-max-age]').wait_for(timeout=5000)
    page.locator('[data-rtest-max-age]').fill('14')
    page.get_by_role('button', name='Save').last.click()
    assert _wait_for_call(app, ('PUT', '/api/pbs/verify-schedule'))
    assert _body(app, '/api/pbs/verify-schedule')['max_age_days'] == 14
    assert not app.errors, app.errors


def test_runtime_a_refused_schedule_says_why(open_app):
    extra = _reads({('PUT', '/api/pbs/verify-schedule'): (400, {'error': 'hour is a whole number from 0 to 23'})})
    app = open_app(extra, layout='modern')
    page = _open_tab(app, 'modern')
    page.locator('[data-rtest-edit-schedule]').click()
    page.locator('[data-rtest-max-age]').wait_for(timeout=5000)
    page.get_by_role('button', name='Save').last.click()
    page.get_by_text('hour is a whole number from 0 to 23').wait_for(timeout=5000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_reads_and_offers_no_change(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _open_tab(app, layout)
    assert page.locator('[data-rtest-row]').count() == 3
    assert page.locator('[data-rtest-readonly]').count() == 1
    for sel in ('[data-rtest-save]', '[data-rtest-edit-schedule]', '[data-rtest-rule-form]', '[data-rtest-rule-remove="guest:101"]'):
        assert page.locator(sel).count() == 0, sel
    assert page.locator('[data-rtest-field="rto"]').is_disabled()
    page.locator('[data-rtest-row="100"]').click()
    page.locator('[data-rtest-history="t2"]').wait_for(timeout=5000)
    assert not [c for c in app.server.calls if c[0] != 'GET' and ('recovery' in c[1] or 'verify' in c[1])]
    assert not app.errors, app.errors


def test_runtime_a_confined_caller_sees_its_report_without_the_settings(open_app):
    confined = {'cluster': {'rto_minutes': 10}, 'guests': [], 'tags': [], 'can_edit': False, 'limits': {}}
    app = open_app(_reads({('GET', '/api/clusters/c1/recovery-settings'): (200, confined)}), layout='modern', admin=False,
                   permissions=['backup.view', 'vm.view', 'storage.view'])
    page = _open_tab(app, 'modern')
    assert page.locator('[data-rtest-settings]').count() == 0
    assert page.locator('[data-rtest-edit-schedule]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_tab_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datenspeicher\s*$')).first.click()
    tab = page.locator('[data-rtest-tab]').first
    assert tab.inner_text().strip() == 'Wiederherstellungstests'
    tab.click()
    page.locator('[data-rtest-row]').first.wait_for(timeout=8000)
    text = page.locator('[data-rtest-panel="c1"]').inner_text()
    assert 'Wöchentlicher Lauf' in text and 'Nie getestet' in text and 'Fehlschlagend' in text
    assert not app.errors, app.errors


def test_runtime_cloud_shows_the_guests_to_look_at(open_app):
    extra = _reads({('GET', '/api/clusters/c1/datacenter/backup'): (200, []),
                    ('GET', '/api/clusters/c1/datacenter/backup/last-runs'): (200, {'jobs': {}})})
    app = open_app(extra, layout='cloud')
    page = app.page
    page.locator('.cloud-shell').get_by_text('Backups', exact=True).first.click()
    page.locator('[data-rtest-cloud="c1"] [data-rtest-row]').first.wait_for(timeout=8000)
    rows = page.locator('[data-rtest-cloud="c1"] [data-rtest-row]')
    assert rows.evaluate_all('rs => rs.map(r => r.dataset.rtestRow)') == ['101', '102']
    kpi = page.locator('[data-rtest-cloud="c1"] .cloud-kpi', has_text='Not tested recently')
    assert kpi.inner_text().split()[0] == '1'
    assert page.locator('[data-rtest-cloud="c1"] [data-rtest-csv]').get_attribute('href').endswith('/api/clusters/c1/recovery-report?format=csv')
    _shot(page, 'rtest_cloud.png')
    assert not app.errors, app.errors


# --- the alert rule ------------------------------------------------------------------------------

ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [
        {'id': 'r9', 'name': 'Restore tests', 'cluster_id': 'c1', 'metric': 'restore_test_age', 'operator': 'event',
         'threshold': 14, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
         'notify_resolved': True, 'severity': 'auto', 'backup_exclude_tags': ['no-backup', 'lab']}]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': []}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/r9'): (200, {'success': True, 'alert': {}}),
}


def _to_alerts(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*(Alerts|Alarme)\s*$')).first.click()
    page.locator('[data-alert-rule="r9"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_alert_rule(open_app, layout):
    extra = dict(ALERT_READS)
    extra.update(SSE_TOKEN)
    app = open_app(extra, layout=layout)
    page = _to_alerts(app, layout)
    assert 'No restore test passed in 14 days - except tagged no-backup, lab' in page.locator('[data-alert-rule="r9"]').inner_text()
    page.locator('button', has_text='New Alert').first.click()
    page.locator('select[name="metric"]').select_option('restore_test_age')
    fields = page.locator('[data-event-fields="restore_test_age"]')
    fields.wait_for(timeout=3000)
    assert fields.locator('input[name="threshold"]').input_value() == '30'
    assert fields.locator('input[name="backup_exclude_tags"]').input_value() == 'no-backup'
    assert 'A test that passes clears it' in page.locator('[data-event-help]').inner_text()
    assert page.locator('select[name="target_type"] option').evaluate_all('o => o.map(x => x.value)') == ['cluster', 'node', 'vm']
    page.locator('input[name="name"]').fill('Restore tests')
    fields.locator('input[name="threshold"]').fill('7')
    fields.locator('input[name="backup_exclude_tags"]').fill('no-backup, lab')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = _body(app, '/api/clusters/c1/alerts')
    for k, v in {'metric': 'restore_test_age', 'operator': 'event', 'threshold': 7,
                 'backup_exclude_tags': 'no-backup, lab', 'notify_resolved': True}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors
