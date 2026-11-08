"""Node clock drift and guest restart loops in the alert dialog and the rule list.

The dialog offers both as event rules: a clock rule takes an allowed offset in seconds and
the cluster or one node, never a guest; a restart rule takes a number of starts and a window
in minutes. The list says what each rule watches. The rules themselves are tested in
tests/test_alert_clock_restart.py. Source checks read web/src and the bundle; the runtime
tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py, in both layouts, as an active instance and as a standby, in English and
German. They skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _classes,  # noqa: F401
                        _wait_for_call, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')

KEYS = ['clockDriftTitle', 'clockDriftHelp', 'clockDriftLimit', 'clockDriftSummary',
        'restartLoopTitle', 'restartLoopHelp', 'restartLoopStarts', 'restartLoopWindow', 'restartLoopSummary']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _added_blocks():
    dash = _read('web', 'src', 'dashboard.js')
    return [
        _between(dash, "{alertMetricSel === 'clock_drift' && (", "{alertMetricSel !== 'rolling_update' && ("),
        _between(dash, "if (alert.metric === 'clock_drift')", 'return `${alert.metric?.toUpperCase()}'),
        _between(dash, '<option value="clock_drift">', '</select>'),
    ]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used():
    src = _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('((?:clockDrift|restartLoop)[A-Za-z]*)'\)", src))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, marks in (('clockDriftSummary', ('{n}',)), ('restartLoopSummary', ('{n}', '{m}'))):
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9 and all(m in v for v in values for m in marks), (key, values)


def test_the_keys_sit_with_the_other_alert_rules_and_the_german_block_keeps_its_flag():
    tr = _read('web', 'src', 'translations.js')
    assert tr.index('            de: {') < tr.index('clockDriftTitle: "Uhrzeit-Abweichung der Nodes"') \
        < tr.index('            en: {')
    for block in re.split(r'^            [a-z]{2}: \{$', tr, flags=re.M)[1:]:
        lines = [ln.strip().split(':', 1)[0] for ln in block.splitlines()]
        at = lines.index('zfsAlertStateOnly')
        assert lines[at + 1:at + 1 + len(KEYS)] == KEYS
    assert "{ code: 'de', flag: '🇦🇹'" in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_what_this_change_added():
    for block in _added_blocks():
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _added_blocks():
        names |= _classes(block)
    missing = sorted(n for n in names - {'field'} if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_a_clock_rule_offers_no_guest_target():
    dash = _read('web', 'src', 'dashboard.js')
    # the QDevice rule (#1137) is a node rule as well and sits in the same condition
    # and so does the Ceph OSD latency rule
    assert ("{alertMetricSel !== 'ceph_osd_latency' && alertMetricSel !== 'zfs_health' && "
            "alertMetricSel !== 'clock_drift' && alertMetricSel !== 'qdevice' && <option value=\"vm\">") in dash
    assert "'zfs_health', 'clock_drift', 'restart_loop', 'qdevice'];" in dash
    assert "payload.restart_window_minutes = parseInt(form.restart_window_minutes.value)" in dash


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('React.createElement("option",{value:"clock_drift"}',
                   'React.createElement("option",{value:"restart_loop"}',
                   'data-event-fields":"restart_loop"', 'restart_window_minutes', 'clockDriftSummary'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

CLOCK_RULE = {'id': 'k1', 'name': 'Clocks', 'cluster_id': 'c1', 'metric': 'clock_drift', 'operator': 'event',
              'threshold': 2, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
              'notify_resolved': True, 'severity': 'auto'}
LOOP_RULE = {'id': 'l1', 'name': 'Loops', 'cluster_id': 'c1', 'metric': 'restart_loop', 'operator': 'event',
             'threshold': 4, 'restart_window_minutes': 30, 'target_type': 'cluster', 'target_id': None,
             'channels': [], 'enabled': True, 'notify_resolved': True, 'severity': 'auto'}
CLOCK_INCIDENT = {'id': 'i7', 'alert_id': 'k1', 'severity': 'warning', 'metric': 'clock_drift', 'operator': 'event',
                  'message': 'The clock of node pve1 is 10.2 s ahead of PegaProx, the limit is 2 s.',
                  'target_type': 'node', 'target_name': 'pve1', 'current_value': 10.2, 'threshold': 2,
                  'triggered_at': '2026-10-07T01:00:00', 'last_fired_at': '2026-10-07T01:00:00', 'acked_at': None,
                  'acked_by': None, 'escalation_step': 0, 'object_key': 'clock:pve1', 'muted_until': None}
LOOP_INCIDENT = {'id': 'i8', 'alert_id': 'l1', 'severity': 'warning', 'metric': 'restart_loop', 'operator': 'event',
                 'message': 'web01 (100) on node pve1 started 5 times in the last 30 minutes',
                 'target_type': 'vm', 'target_name': 'web01 (100)', 'current_value': 5, 'threshold': 4,
                 'triggered_at': '2026-10-07T01:05:00', 'last_fired_at': '2026-10-07T01:05:00', 'acked_at': None,
                 'acked_by': None, 'escalation_step': 0, 'object_key': 'vm:100', 'muted_until': None}
ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [CLOCK_RULE, LOOP_RULE]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': [CLOCK_INCIDENT, LOOP_INCIDENT]}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/l1'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/k1'): (200, {'success': True, 'alert': {}}),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(ALERT_READS)
        extra.update(SSE_TOKEN)
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra=extra, **kw))
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
    page.locator('[data-alert-rule="l1"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _new_rule(page, metric):
    page.locator('button', has_text='New Alert').first.click()
    sel = page.locator('select[name="metric"]')
    sel.wait_for(timeout=3000)
    sel.select_option(metric)
    page.locator(f'[data-event-fields="{metric}"]').wait_for(timeout=3000)
    return page.locator(f'[data-event-fields="{metric}"]')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_rules_and_their_incidents_in_the_list(open_app, layout):
    app = open_app(layout=layout)
    page = _to_alerts(app, layout)
    assert 'Node clock more than 2 s off' in page.locator('[data-alert-rule="k1"]').inner_text()
    assert '4 starts within 30 min' in page.locator('[data-alert-rule="l1"]').inner_text()
    assert '10.2 s ahead of PegaProx' in page.locator('[data-active-alert="i7"]').inner_text()
    assert 'started 5 times' in page.locator('[data-active-alert="i8"]').inner_text()
    # a clock incident is muted for its node, a loop for its guest
    page.locator('[data-active-alert="i7"] button[title="Mute"]').click()
    assert 'every rule for pve1' in page.locator('[data-mute-menu]').inner_text()
    page.locator('[data-active-alert="i8"] button[title="Mute"]').click()
    assert 'every rule for web01 (100)' in page.locator('[data-mute-menu]').inner_text()
    _shot(page, f'{layout}_alerts_clock_restart.png')
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_a_clock_rule_needs(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    fields = _new_rule(page, 'clock_drift')
    assert fields.locator('input[name="threshold"]').input_value() == '2'
    assert 'whole seconds' in page.locator('[data-event-help]').inner_text()
    # a clock belongs to a node or to every node of the cluster, never to a guest
    assert page.locator('select[name="target_type"] option').evaluate_all('o => o.map(x => x.value)') == [
        'cluster', 'node']
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('input[name="notify_resolved"]').is_checked()
    page.locator('input[name="name"]').fill('Clocks')
    page.locator('select[name="target_type"]').select_option('node')
    page.locator('input[name="target_id"]').fill('pve1')
    fields.locator('input[name="threshold"]').fill('5')
    _shot(page, 'modern_alerts_dialog_clock.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    # the list is read again on the same path right after, with no body
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'name': 'Clocks', 'metric': 'clock_drift', 'operator': 'event', 'threshold': 5,
                 'target_type': 'node', 'target_id': 'pve1', 'notify_resolved': True}.items():
        assert body.get(k) == v, (k, body)
    assert 'restart_window_minutes' not in body
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_a_restart_rule_needs(open_app):
    app = open_app(layout='corporate')
    page = _to_alerts(app, 'corporate')
    fields = _new_rule(page, 'restart_loop')
    assert fields.locator('input[name="threshold"]').input_value() == '3'
    assert fields.locator('input[name="restart_window_minutes"]').input_value() == '15'
    assert 'start and reboot tasks' in page.locator('[data-event-help]').inner_text()
    # a loop can be watched on one guest
    assert page.locator('select[name="target_type"] option[value="vm"]').count() == 1
    page.locator('input[name="name"]').fill('Loops of 100')
    page.locator('select[name="target_type"]').select_option('vm')
    page.locator('input[name="target_id"]').fill('100')
    fields.locator('input[name="threshold"]').fill('4')
    fields.locator('input[name="restart_window_minutes"]').fill('45')
    _shot(page, 'corporate_alerts_dialog_restart.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'metric': 'restart_loop', 'operator': 'event', 'threshold': 4, 'restart_window_minutes': 45,
                 'target_type': 'vm', 'target_id': '100'}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors


def test_runtime_editing_keeps_what_was_saved(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    page.locator('[data-alert-rule="l1"] button[title="Edit Alert"]').click()
    fields = page.locator('[data-event-fields="restart_loop"]')
    fields.wait_for(timeout=3000)
    assert fields.locator('input[name="threshold"]').input_value() == '4'
    assert fields.locator('input[name="restart_window_minutes"]').input_value() == '30'
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/alerts/l1'))
    body = app.server.bodies['/api/clusters/c1/alerts/l1'][-1]
    assert (body['threshold'], body['restart_window_minutes']) == (4, 30)

    page.locator('[data-alert-rule="k1"] button[title="Edit Alert"]').click()
    page.locator('[data-event-fields="clock_drift"]').wait_for(timeout=3000)
    assert page.locator('[data-event-fields="clock_drift"] input[name="threshold"]').input_value() == '2'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_them_and_offers_no_change(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _to_alerts(app, layout)
    assert 'Node clock more than 2 s off' in page.locator('[data-alert-rule="k1"]').inner_text()
    assert page.locator('[data-active-alert="i7"]').count() == 1
    assert page.locator('button', has_text='New Alert').count() == 0
    assert page.locator('[data-alert-rule="l1"] button[title="Edit Alert"]').count() == 0
    assert page.locator('[data-active-alert="i7"] button[title="Mute"]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/alert' in c[1]]
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = _to_alerts(app)
    assert 'Node-Uhr mehr als 2 s daneben' in page.locator('[data-alert-rule="k1"]').inner_text()
    assert '4 Starts innerhalb von 30 Min.' in page.locator('[data-alert-rule="l1"]').inner_text()
    page.locator('button', has_text=re.compile(r'Neuer Alarm|New Alert')).first.click()
    sel = page.locator('select[name="metric"]')
    sel.wait_for(timeout=3000)
    labels = sel.locator('option').all_inner_texts()
    assert 'Uhrzeit-Abweichung der Nodes' in labels and 'Neustart-Schleifen von Gästen' in labels
    sel.select_option('restart_loop')
    fields = page.locator('[data-event-fields="restart_loop"]')
    assert 'Innerhalb von (Minuten)' in fields.inner_text()
    _shot(page, 'modern_alerts_dialog_restart_de.png')
    assert not app.errors, app.errors
