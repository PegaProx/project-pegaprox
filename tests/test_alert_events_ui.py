"""The event rules, the mutes and the resolved note in Automation > Alerts.

The source checks read web/src and the bundle; the runtime tests drive the built bundle
in headless Chromium against the fake server of tests/test_ha_ui.py, in Modern and
Corporate, as an active instance and as a standby, in English and German. They skip
where Playwright is not installed. The routes behind the page are tested in
tests/test_alert_events.py.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import BASE, CLUSTER, VM, SSE_TOKEN, _App, _FakeServer, _toasts, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


def _alerts_tab(dash):
    return dash[dash.index("{automationSubTab === 'alerts' && ("):dash.index("{automationSubTab === 'affinity' && (")]


def _modal(dash):
    start = dash.index('{/* Alert Modal - NS Jan 2026')
    return dash[start:dash.index('{/* Affinity Rule Modal', start)]


NEW_KEYS = ['alertMetricCeph', 'alertMetricSnapshots', 'alertTaskHelp', 'alertCephHelp', 'alertReplHelp',
            'alertSnapHelp', 'alertTaskType', 'alertTaskStatus', 'alertPatternHelp', 'alertTaskWarnings',
            'alertCephLevel', 'alertCephWarnPlus', 'alertCephErrOnly', 'alertReplLag', 'alertSnapDays',
            'alertSnapIgnorePolicy', 'alertNotifyResolved', 'alertSummaryTask', 'alertSummaryRepl',
            'alertSummarySnap', 'alertMute', 'alertMuted', 'alertUnmute', 'alertMuteFor', 'alertMute1h',
            'alertMute4h', 'alertMute1d', 'alertMute7d', 'alertMuteWholeObject', 'alertMutes',
            'alertMuteEveryRule', 'alertMuteDone', 'alertUnmuteDone']


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', NEW_KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 10, f'{key} is in {found} of 10 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one(dash):
    used = set(re.findall(r"t\('(alert(?:Metric|Task|Ceph|Repl|Snap|Notify|Summary|Mute|Muted|Unmute|Pattern)[A-Za-z0-9]*)'\)", dash))
    # the durations go through t(key) from one list
    menu = dash[dash.index('const renderMuteChoices = '):dash.index('const fmtMuteUntil = ')]
    assert '{t(key)}' in menu
    used |= set(re.findall(r"\[\d+, '(alertMute\d[hd])'\]", menu))
    assert used == set(NEW_KEYS), (sorted(used - set(NEW_KEYS)), sorted(set(NEW_KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, ph in (('alertMuted', '{time}'), ('alertMuteWholeObject', '{name}'), ('alertSummaryTask', '{type}'),
                    ('alertSummaryRepl', '{n}'), ('alertSummarySnap', '{n}')):
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 10 and all(ph in v for v in values), (key, values)


def _added_blocks(dash):
    """The pieces of dashboard.js this change wrote (the code around them is older)."""
    def between(a, b):
        s = dash.index(a)
        return dash[s:dash.index(b, s)]
    return [
        between('// LW Oct 2026 - mutes of the cluster', 'const [sessionExpired'),
        between('// LW Oct 2026 - mutes: a rule, an incident', '// Cluster Affinity Rules Functions'),
        between('{/* LW Oct 2026 - what an event rule watches', "{t('notifyVia') || 'Notify via'}"),
        between('{/* LW Oct 2026 - what is muted right now', "{automationSubTab === 'affinity' && ("),
        between("// LW Oct 2026 - the event rules' own fields", 'if (editingAlert) {'),
    ]


def test_no_em_dash_in_what_this_change_added(dash):
    for block in _added_blocks(dash):
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in NEW_KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icon_exists_and_takes_a_class():
    icons = _read('web', 'src', 'icons.js')
    assert re.search(r'BellOff: \(\{ className, style \} = \{\}\) => \(', icons)


def test_acting_controls_sit_behind_the_standby_flag(dash):
    tab = _alerts_tab(dash)
    for opener in ("setMuteMenu(muteMenu && muteMenu.kind === 'incident'", "onClick={() => unmuteAlert(m.id)}",
                   "onClick={() => unmuteAlert(ruleMute(alert.id).id)}",
                   "setMuteMenu(muteMenu && muteMenu.kind === 'rule'"):
        at = tab.index(opener)
        # the rule row's buttons share one guard with Edit and Delete; the runtime test
        # below shows the standby renders none of them
        assert '!haReadOnly && (' in tab[max(0, at - 2000):at], opener
    # the menus themselves too, should a stale one be open when the role changes
    assert tab.count('!haReadOnly && renderMuteChoices(') == 2


def test_every_class_is_in_the_static_tailwind_build(dash):
    from test_ha_ui import _classes
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _added_blocks(dash):
        names |= _classes(block)
    names |= _classes(_alerts_tab(dash))
    # JS names inside ${...}
    names -= {'field'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('React.createElement("option",{value:"task_failed"}', 'data-mute-menu', 'alertMuteWholeObject',
                   'notify_resolved', 'snapshot_ignore_policy'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

RULES = [
    {'id': 'r1', 'name': 'Nightly backups', 'cluster_id': 'c1', 'metric': 'task_failed', 'operator': 'event',
     'threshold': 1, 'task_type': 'vzdump', 'task_status': '', 'task_warnings': False, 'target_type': 'cluster',
     'target_id': None, 'channels': ['email'], 'enabled': True, 'notify_resolved': True, 'severity': 'auto'},
    {'id': 'r2', 'name': 'Ceph', 'cluster_id': 'c1', 'metric': 'ceph_health', 'operator': 'event', 'threshold': 1,
     'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True, 'notify_resolved': True},
    {'id': 'r3', 'name': 'CPU high', 'cluster_id': 'c1', 'metric': 'cpu', 'operator': '>', 'threshold': 90,
     'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True},
    {'id': 'r4', 'name': 'Old snapshots', 'cluster_id': 'c1', 'metric': 'snapshot_age', 'operator': 'event',
     'threshold': 30, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
     'snapshot_ignore_policy': True, 'notify_resolved': False},
]
ACTIVE = [
    {'id': 'i1', 'alert_id': 'r1', 'severity': 'warning', 'metric': 'task_failed', 'operator': 'event',
     'message': 'Backup of web01 (100) on node pve1 failed: job errors', 'target_type': 'vm',
     'target_name': 'web01 (100)', 'current_value': 1, 'threshold': 1, 'triggered_at': '2026-10-04T01:00:00',
     'last_fired_at': '2026-10-04T01:00:00', 'acked_at': None, 'acked_by': None, 'escalation_step': 0,
     'object_key': 'task:pve1:vzdump:100', 'muted_until': None},
    {'id': 'i2', 'alert_id': 'r2', 'severity': 'critical', 'metric': 'ceph_health', 'operator': 'event',
     'message': 'Ceph on Testi reports HEALTH_ERR', 'target_type': 'cluster', 'target_name': 'Testi',
     'current_value': 2, 'threshold': 1, 'triggered_at': '2026-10-04T02:00:00',
     'last_fired_at': '2026-10-04T02:00:00', 'acked_at': None, 'acked_by': None, 'escalation_step': 0,
     'object_key': 'ceph', 'muted_until': '2026-10-05T10:00:00'},
]
MUTES = [
    {'id': 'm1', 'cluster_id': 'c1', 'rule_id': 'r2', 'object_key': '', 'object_label': '',
     'until': '2026-10-05T10:00:00', 'reason': '', 'created_by': 'admin', 'created_at': '2026-10-04T09:00:00'},
    {'id': 'm2', 'cluster_id': 'c1', 'rule_id': '', 'object_key': 'vm:100', 'object_label': 'web01 (100)',
     'until': '2026-10-04T23:00:00', 'reason': '', 'created_by': 'admin', 'created_at': '2026-10-04T09:00:00'},
]
READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': RULES}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': ACTIVE}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': MUTES}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
}
WRITES = {
    ('POST', '/api/clusters/c1/alert-mutes'): (200, {'success': True, 'mute': {}}),
    ('DELETE', '/api/clusters/c1/alert-mutes/m1'): (200, {'success': True}),
    ('DELETE', '/api/clusters/c1/alert-mutes/m2'): (200, {'success': True}),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/r1'): (200, {'success': True, 'alert': {}}),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(READS)
        extra.update(SSE_TOKEN)
        extra.update(kw.pop('extra', {}))
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


def _to_alerts(app, layout='modern'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*(Alerts|Alarme)\s*$')).first.click()
    page.locator('[data-alert-rule="r1"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _sent(app, method, path):
    """The bodies of one method on one path, in order (the fake server keeps them per path)."""
    out, i = [], 0
    for m, p in app.server.calls:
        if p != path:
            continue
        if m == method:
            out.append(app.server.bodies[path][i])
        i += 1
    return out


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_rules_incidents_and_mutes_show_and_act(open_app, layout):
    app = open_app(role='standalone', layout=layout, extra=WRITES)
    page = _to_alerts(app, layout)

    # what each rule watches, in one line
    assert 'Failed tasks: vzdump' in page.locator('[data-alert-rule="r1"]').inner_text()
    assert 'HEALTH_ERR only' in page.locator('[data-alert-rule="r2"]').inner_text()
    assert 'CPU > 90%' in page.locator('[data-alert-rule="r3"]').inner_text()
    assert 'Snapshots older than 30 days' in page.locator('[data-alert-rule="r4"]').inner_text()
    # a muted rule and a muted incident say so
    assert page.locator('[data-alert-rule="r2"] [data-rule-muted]').count() == 1
    assert page.locator('[data-alert-rule="r1"] [data-rule-muted]').count() == 0
    assert 'Muted until' in page.locator('[data-active-alert="i2"] [data-alert-muted]').inner_text()
    # only the incident that is not muted offers a mute
    assert page.locator('[data-active-alert="i1"] button[title="Mute"]').count() == 1
    assert page.locator('[data-active-alert="i2"] button[title="Mute"]').count() == 0
    # the list of mutes: the rule by its name, the guest under every rule
    mutes = page.locator('[data-alert-mutes]').inner_text()
    assert 'Ceph' in mutes and 'Every rule / web01 (100)' in mutes and 'admin' in mutes
    _shot(page, f'{layout}_alerts_list.png')

    # mute an incident: everything about its guest, for a day
    page.locator('[data-active-alert="i1"] button[title="Mute"]').click()
    menu = page.locator('[data-mute-menu]')
    menu.wait_for(timeout=3000)
    for label in ('1 hour', '4 hours', '1 day', '7 days'):
        assert menu.get_by_role('button', name=label).count() == 1
    menu.get_by_text('every rule for web01 (100)').click()
    _shot(page, f'{layout}_alerts_mute_menu.png')
    menu.get_by_role('button', name='1 day').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alert-mutes'))
    posted = _sent(app, 'POST', '/api/clusters/c1/alert-mutes')[-1]
    assert posted == {'active_alert_id': 'i1', 'minutes': 1440, 'whole_object': True}, posted
    page.wait_for_timeout(300)
    assert 'Alert muted' in ' '.join(_toasts(page))
    assert page.locator('[data-mute-menu]').count() == 0

    # mute a rule for an hour
    page.locator('[data-alert-rule="r1"] button[title="Mute"]').click()
    page.locator('[data-mute-menu]').get_by_role('button', name='1 hour').click()
    page.wait_for_timeout(300)
    assert _sent(app, 'POST', '/api/clusters/c1/alert-mutes')[-1] == {'rule_id': 'r1', 'minutes': 60}

    # lift one from the rule row, one from the list
    page.locator('[data-alert-rule="r2"] button[title="Unmute"]').click()
    assert _wait_for_call(app, ('DELETE', '/api/clusters/c1/alert-mutes/m1'))
    page.locator('[data-alert-mute="m2"]').get_by_role('button', name='Unmute').click()
    assert _wait_for_call(app, ('DELETE', '/api/clusters/c1/alert-mutes/m2'))
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_each_event_rule_needs(open_app):
    app = open_app(role='standalone', layout='modern', extra=WRITES)
    page = _to_alerts(app)
    page.locator('button', has_text='New Alert').first.click()
    metric = page.locator('select[name="metric"]')
    metric.wait_for(timeout=3000)
    # a CPU rule: comparison, target, no resolved note unless asked
    assert page.locator('select[name="operator"]').count() == 1
    assert not page.locator('input[name="notify_resolved"]').is_checked()

    metric.select_option('task_failed')
    assert page.locator('[data-event-fields="task_failed"]').count() == 1
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('input[name="task_type"]').input_value() == 'vzdump'
    assert page.locator('input[name="notify_resolved"]').is_checked()
    assert 'clears when it succeeds again' in page.locator('[data-event-help]').inner_text()
    page.locator('input[name="name"]').fill('Backups')
    page.locator('input[name="task_status"]').fill('job errors')
    page.locator('input[name="task_warnings"]').check()
    _shot(page, 'modern_alerts_dialog_task.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = _sent(app, 'POST', '/api/clusters/c1/alerts')[-1]
    for k, v in {'name': 'Backups', 'metric': 'task_failed', 'operator': 'event', 'threshold': 1,
                 'task_type': 'vzdump', 'task_status': 'job errors', 'task_warnings': True,
                 'notify_resolved': True, 'target_type': 'cluster'}.items():
        assert body.get(k) == v, (k, body)

    page.locator('button', has_text='New Alert').first.click()
    metric = page.locator('select[name="metric"]')
    metric.select_option('ceph_health')
    # about the whole cluster: no target to pick
    assert page.locator('select[name="target_type"]').count() == 0
    assert page.locator('[data-event-fields="ceph_health"] select[name="threshold"] option').all_inner_texts() == [
        'HEALTH_WARN or worse', 'HEALTH_ERR only']
    _shot(page, 'modern_alerts_dialog_ceph.png')
    metric.select_option('replication')
    assert page.locator('[data-event-fields="replication"] input[name="threshold"]').input_value() == '60'
    assert page.locator('select[name="target_type"]').count() == 1
    metric.select_option('snapshot_age')
    assert page.locator('[data-event-fields="snapshot_age"] input[name="threshold"]').input_value() == '14'
    assert page.locator('input[name="snapshot_ignore_policy"]').is_checked()
    page.locator('input[name="name"]').fill('Snapshots')
    page.locator('input[name="snapshot_ignore_policy"]').uncheck()
    page.locator('form button[type="submit"]').click()
    page.wait_for_timeout(400)
    body = _sent(app, 'POST', '/api/clusters/c1/alerts')[-1]
    assert (body['metric'], body['threshold'], body['snapshot_ignore_policy']) == ('snapshot_age', 14, False), body
    assert not app.errors, app.errors


def test_runtime_editing_an_event_rule_keeps_its_fields(open_app):
    app = open_app(role='standalone', layout='modern', extra=WRITES)
    page = _to_alerts(app)
    page.locator('[data-alert-rule="r4"] button[title="Edit Alert"]').click()
    page.locator('[data-event-fields="snapshot_age"]').wait_for(timeout=3000)
    assert page.locator('input[name="threshold"]').input_value() == '30'
    assert not page.locator('input[name="notify_resolved"]').is_checked()     # the rule said no
    page.keyboard.press('Escape')
    page.locator('form button', has_text='Cancel').click()
    page.locator('[data-alert-rule="r1"] button[title="Edit Alert"]').click()
    page.locator('[data-event-fields="task_failed"]').wait_for(timeout=3000)
    assert page.locator('input[name="task_type"]').input_value() == 'vzdump'
    page.locator('input[name="task_type"]').fill('vzdump|qmrestore')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/alerts/r1'))
    assert _sent(app, 'PUT', '/api/clusters/c1/alerts/r1')[-1]['task_type'] == 'vzdump|qmrestore'
    assert not app.errors, app.errors


def test_runtime_a_refused_rule_says_why(open_app):
    refused = {('POST', '/api/clusters/c1/alerts'): (
        400, {'error': 'task type: a repeat inside a repeat can take very long to fail'})}
    app = open_app(role='standalone', layout='modern', extra=refused)
    page = _to_alerts(app)
    page.locator('button', has_text='New Alert').first.click()
    page.locator('select[name="metric"]').select_option('task_failed')
    page.locator('input[name="name"]').fill('x')
    page.locator('input[name="task_type"]').fill('(a+)+')
    page.locator('form button[type="submit"]').click()
    page.wait_for_timeout(500)
    assert any('a repeat inside a repeat' in x for x in _toasts(page)), _toasts(page)
    # the dialog stays open with what was typed
    assert page.locator('input[name="task_type"]').input_value() == '(a+)+'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_mutes_but_offers_nothing_that_acts(open_app, layout):
    app = open_app(role='standby', layout=layout)
    page = _to_alerts(app, layout)
    assert page.locator('[data-alert-rule="r2"] [data-rule-muted]').count() == 1
    assert page.locator('[data-active-alert="i2"] [data-alert-muted]').count() == 1
    assert page.locator('[data-alert-mutes]').count() == 1
    assert page.locator('button[title="Mute"]').count() == 0
    assert page.locator('button[title="Unmute"]').count() == 0
    assert page.locator('[data-alert-mutes] button').count() == 0
    assert page.locator('button', has_text='New Alert').count() == 0
    _shot(page, f'{layout}_alerts_standby.png')
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'alert' in c[1]]
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(role='standalone', layout='modern', language='de', extra=WRITES)
    page = _to_alerts(app)
    assert 'Fehlgeschlagene Aufgaben: vzdump' in page.locator('[data-alert-rule="r1"]').inner_text()
    assert 'Nur HEALTH_ERR' in page.locator('[data-alert-rule="r2"]').inner_text()
    assert 'Stumm bis' in page.locator('[data-active-alert="i2"]').inner_text()
    assert page.locator('[data-active-alert="i1"] button[title="Stummschalten"]').count() == 1
    assert 'Alle Regeln / web01 (100)' in page.locator('[data-alert-mutes]').inner_text()
    page.locator('[data-active-alert="i1"] button[title="Stummschalten"]').click()
    assert 'alle Regeln für web01 (100)' in page.locator('[data-mute-menu]').inner_text()
    _shot(page, 'modern_alerts_de.png')
    assert not app.errors, app.errors
