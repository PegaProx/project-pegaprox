"""Guests without a backup job in the All Clusters overview, and the alert rule for them.

The source checks read web/src and the bundle; the runtime tests drive the built bundle
in headless Chromium against the fake server of tests/test_ha_ui.py, in Modern and
Corporate, as an active instance and as a standby, in English and German. They skip
where Playwright is not installed. The route and the alert source behind the page are
tested in tests/test_backup_coverage.py.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, _classes, _toasts, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']

KEYS = ['backupCoverageTitle', 'backupCoverageDesc', 'backupCoverageHideTagged', 'backupCoverageHidden',
        'backupCoverageNotChecked', 'backupCoverageOffline', 'backupCoverageDenied', 'backupCoverageUnreadable',
        'backupCoverageShowAll', 'backupCoverageAllCovered', 'backupCoverageNoMatch', 'backupCoverageExpand',
        'backupCoverageHelp', 'backupCoverageGrace', 'backupCoverageExcludeTags', 'backupCoverageTagsHint',
        'backupCoverageSummary', 'backupCoverageExcept']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _panel():
    src = _read('web', 'src', 'vm_modals.js')
    start = src.index('// LW Oct 2026 - the guests no backup job covers')
    return src[start:src.index('// LW: All Clusters Overview - GitHub Feature Request #16', start)]


def _dialog_bits():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('{/* LW Oct 2026 - a guest tagged like this is left out on purpose')
    fields = dash[start:dash.index('{alertMetricSel !== \'rolling_update\' && (', start)]
    summary = dash[dash.index("if (alert.metric === 'backup_coverage') {"):dash.index("return `${alert.metric?.toUpperCase()}")]
    return fields, summary


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 10, f'{key} is in {found} of 10 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    src = _read('web', 'src', 'vm_modals.js') + _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('(backupCoverage[A-Za-z]*)'\)", src))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, ph in (('backupCoverageHidden', '{n}'), ('backupCoverageShowAll', '{n}'),
                    ('backupCoverageSummary', '{n}'), ('backupCoverageExcept', '{tags}')):
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 10 and all(ph in v for v in values), (key, values)


def test_no_em_dash_in_what_this_change_added():
    fields, summary = _dialog_bits()
    for block in (_panel(), fields, summary):
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icon_exists_and_takes_a_class():
    icons = _read('web', 'src', 'icons.js')
    assert re.search(r'ArchiveX: \(\{ className, style \} = \{\}\) => \(', icons)
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _panel()))
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    assert used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    # the shell's light-theme overrides name classes the build does not have (bg-amber-500/20
    # is one): only what defines a class counts, in dark as in light
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    fields, summary = _dialog_bits()
    names = _classes(_panel()) | _classes(fields) | _classes(summary)
    names -= {'field'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_panel_offers_nothing_that_acts():
    """Refresh reads, the chevron folds, a row opens the guest: no write from here, so a
    standby shows it unchanged."""
    panel = _panel()
    assert "method:" not in panel and 'POST' not in panel and 'DELETE' not in panel
    assert panel.count('authFetch(') == 0 and panel.count('fetch(`${API_URL}/backup-coverage') == 1


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function GuestsWithoutBackup(', '/backup-coverage', 'data-backup-coverage-row',
                   'React.createElement("option",{value:"backup_coverage"}', 'backup_exclude_tags', 'ArchiveX'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

COVERAGE = {
    'guests': [
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 100, 'name': 'web01', 'type': 'qemu',
         'node': 'pve1', 'status': 'running', 'template': False, 'tags': []},
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 105, 'name': 'lab', 'type': 'lxc',
         'node': 'pve2', 'status': 'stopped', 'template': False, 'tags': ['lab', 'no-backup']},
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 900, 'name': 'golden', 'type': 'qemu',
         'node': 'pve1', 'status': 'stopped', 'template': True, 'tags': []},
    ],
    'clusters': [
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 3, 'checked_at': 1791000000},
        {'cluster_id': 'c9', 'cluster_name': 'Locked', 'state': 'denied', 'count': 0, 'checked_at': None},
    ],
}
COV = ('GET', '/api/backup-coverage')
RULE = {'id': 'r5', 'name': 'Unprotected', 'cluster_id': 'c1', 'metric': 'backup_coverage', 'operator': 'event',
        'threshold': 2, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
        'notify_resolved': True, 'backup_exclude_tags': ['no-backup', 'scratch']}
ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [RULE]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': []}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/r5'): (200, {'success': True, 'alert': {}}),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(coverage=(200, COVERAGE), **kw):
        extra = dict(SSE_TOKEN)
        extra[COV] = coverage
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _panel_on(app):
    panel = app.page.locator('[data-backup-coverage]')
    panel.wait_for(timeout=10000)
    app.page.locator('[data-backup-coverage-row]').first.wait_for(timeout=5000)
    panel.scroll_into_view_if_needed()
    app.page.wait_for_timeout(200)
    return panel


def _rows(page):
    return page.locator('[data-backup-coverage-row]').evaluate_all('rs => rs.map(r => r.dataset.backupCoverageRow)')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_overview_lists_the_guests_without_a_job(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    panel = _panel_on(app)
    text = panel.inner_text()
    assert 'Guests without a backup job' in text
    # the guest tagged no-backup is left out by default, and the page says so
    assert _rows(page) == ['c1:100', 'c1:900']
    assert page.locator('[data-backup-coverage-count]').inner_text().strip('() ') == '2'
    assert page.locator('[data-backup-coverage-tagged]').inner_text() == '1 hidden by tag'
    row = page.locator('[data-backup-coverage-row="c1:100"]').inner_text()
    for word in ('web01', '100', 'testi', 'pve1', 'running'):
        assert word in row.lower(), (word, row)
    tpl = page.locator('[data-backup-coverage-row="c1:900"]').inner_text().lower()
    assert 'template' in tpl and 'stopped' in tpl
    assert page.locator('[data-backup-coverage-unchecked]').inner_text() == \
        'Not checked: Locked (the API user lacks Sys.Audit)'
    _shot(page, f'{layout}_overview.png')

    # another tag to hide, then none: every guest shows with its tags
    page.locator('[data-backup-coverage-hide]').fill('')
    assert _rows(page) == ['c1:100', 'c1:105', 'c1:900']
    assert 'lab, no-backup' in page.locator('[data-backup-coverage-row="c1:105"]').inner_text()
    assert page.locator('[data-backup-coverage-tagged]').count() == 0
    page.locator('[data-backup-coverage-search]').fill('gold')
    assert _rows(page) == ['c1:900']
    page.locator('[data-backup-coverage-search]').fill('nothing-like-it')
    assert 'No guest matches the filter.' in page.locator('[data-backup-coverage-empty]').inner_text()
    page.locator('[data-backup-coverage-search]').fill('')

    # refresh asks the server to read again
    before = len([u for u in app.server.urls if '/api/backup-coverage' in u])
    panel.locator('button[title="Refresh"]').click()
    page.wait_for_timeout(400)
    asked = [u for u in app.server.urls if '/api/backup-coverage' in u]
    assert len(asked) == before + 1 and asked[-1].endswith('?refresh=1'), asked
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'backup' in c[1]]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_row_opens_the_guest(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _panel_on(app)
    page.locator('[data-backup-coverage-row="c1:100"]').click()
    # the guest's own view: the overview is gone and the cluster's guest list was asked for
    page.locator('[data-backup-coverage]').wait_for(state='detached', timeout=5000)
    assert any(p.startswith('/api/clusters/c1/') for _, p in app.server.calls)
    assert not app.errors, app.errors


def test_runtime_the_fold_is_remembered(open_app):
    app = open_app(layout='modern')
    page = app.page
    panel = _panel_on(app)
    panel.locator('button[title="Collapse"]').click()
    assert page.locator('[data-backup-coverage-row]').count() == 0
    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-backup-coverage]').wait_for(timeout=10000)
    page.wait_for_timeout(500)
    assert page.locator('[data-backup-coverage-row]').count() == 0
    page.locator('[data-backup-coverage] button[title="Expand"]').click()
    page.locator('[data-backup-coverage-row]').first.wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_all_covered(open_app):
    app = open_app(layout='modern', coverage=(200, {'guests': [], 'clusters': [COVERAGE['clusters'][0]]}))
    app.page.locator('[data-backup-coverage-empty]').wait_for(timeout=10000)
    assert app.page.locator('[data-backup-coverage-empty]').inner_text().strip() == 'Every guest is in a backup job.'
    assert app.page.locator('[data-backup-coverage-unchecked]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_it_and_sends_nothing(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = app.page
    panel = _panel_on(app)
    assert _rows(page) == ['c1:100', 'c1:900']
    # refresh reads, the chevron and the title fold the panel; nothing else is a button
    buttons = panel.locator('button').evaluate_all(
        "bs => bs.map(b => b.hasAttribute('data-backup-coverage-fold') ? 'fold' : b.title)")
    assert set(buttons) <= {'Refresh', 'Collapse', 'fold'}, buttons
    panel.locator('button[title="Refresh"]').click()
    page.wait_for_timeout(300)
    _shot(page, f'{layout}_overview_standby.png')
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] not in ('/api/sse/token', '/api/sse/subscribe')]
    assert not app.errors, app.errors


def test_runtime_without_backup_view_there_is_no_panel_and_no_read(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view', 'cluster.view'])
    app.page.wait_for_timeout(1500)
    assert app.page.locator('[data-backup-coverage]').count() == 0
    assert COV not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_refusal_hides_the_panel(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view', 'backup.view'],
                   coverage=(403, {'error': 'Permission denied'}))
    assert _wait_for_call(app, COV)
    app.page.wait_for_timeout(500)
    assert app.page.locator('[data-backup-coverage]').count() == 0


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    panel = _panel_on(app)
    text = panel.inner_text()
    assert 'Gäste ohne Backup-Job' in text and '1 per Tag ausgeblendet' in text
    assert 'Nicht geprüft: Locked (dem API-Benutzer fehlt Sys.Audit)' in text
    _shot(app.page, 'modern_overview_de.png')
    assert not app.errors, app.errors


# --- the alert rule ------------------------------------------------------------------------

def _to_alerts(app, layout='modern'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*(Alerts|Alarme)\s*$')).first.click()
    page.locator('[data-alert-rule="r5"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _sent(app, method, path):
    out, i = [], 0
    for m, p in app.server.calls:
        if p != path:
            continue
        if m == method:
            out.append(app.server.bodies[path][i])
        i += 1
    return out


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_rule_says_what_it_watches(open_app, layout):
    app = open_app(layout=layout, extra=ALERT_READS)
    page = _to_alerts(app, layout)
    assert 'Guests without a backup job (after 2 h) - except tagged no-backup, scratch' in \
        page.locator('[data-alert-rule="r5"]').inner_text()
    _shot(page, f'{layout}_alert_rule.png')
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_the_grace_and_the_tags(open_app):
    app = open_app(layout='modern', extra=ALERT_READS)
    page = _to_alerts(app)
    page.locator('button', has_text='New Alert').first.click()
    metric = page.locator('select[name="metric"]')
    metric.wait_for(timeout=3000)
    metric.select_option('backup_coverage')
    fields = page.locator('[data-event-fields="backup_coverage"]')
    assert fields.count() == 1
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('select[name="target_type"]').count() == 1
    assert fields.locator('input[name="threshold"]').input_value() == '1'
    assert fields.locator('input[name="backup_exclude_tags"]').input_value() == 'no-backup'
    assert page.locator('input[name="notify_resolved"]').is_checked()
    assert 'Proxmox counts disabled jobs as well' in page.locator('[data-event-help]').inner_text()
    page.locator('input[name="name"]').fill('Unprotected guests')
    fields.locator('input[name="threshold"]').fill('0')
    fields.locator('input[name="backup_exclude_tags"]').fill('no-backup, scratch')
    _shot(page, 'modern_alert_dialog.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = _sent(app, 'POST', '/api/clusters/c1/alerts')[-1]
    for k, v in {'name': 'Unprotected guests', 'metric': 'backup_coverage', 'operator': 'event', 'threshold': 0,
                 'backup_exclude_tags': 'no-backup, scratch', 'notify_resolved': True,
                 'target_type': 'cluster'}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors


def test_runtime_editing_keeps_the_tags(open_app):
    app = open_app(layout='modern', extra=ALERT_READS)
    page = _to_alerts(app)
    page.locator('[data-alert-rule="r5"] button[title="Edit Alert"]').click()
    fields = page.locator('[data-event-fields="backup_coverage"]')
    fields.wait_for(timeout=3000)
    assert fields.locator('input[name="threshold"]').input_value() == '2'
    assert fields.locator('input[name="backup_exclude_tags"]').input_value() == 'no-backup, scratch'
    fields.locator('input[name="backup_exclude_tags"]').fill('no-backup')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/alerts/r5'))
    body = _sent(app, 'PUT', '/api/clusters/c1/alerts/r5')[-1]
    assert (body['metric'], body['threshold'], body['backup_exclude_tags']) == ('backup_coverage', 2, 'no-backup')
    assert not app.errors, app.errors


def test_runtime_a_standby_offers_no_new_rule(open_app):
    app = open_app(layout='modern', role='standby', extra=ALERT_READS)
    page = _to_alerts(app)
    assert page.locator('button', has_text='New Alert').count() == 0
    assert page.locator('[data-alert-rule="r5"] button[title="Edit Alert"]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'alert' in c[1]]
    assert not app.errors, app.errors
