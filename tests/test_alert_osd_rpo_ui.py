"""Ceph OSD latency and replication RPO rules in the alert dialog and the rule list.

The dialog offers both as event rules: an OSD rule takes a limit in ms and the cluster or one
node, never a guest; a replication RPO rule takes minutes (0: twice each job's interval) and
the cluster or one guest, never a node. The list says what each rule watches. The rules
themselves are tested in tests/test_alert_osd_rpo.py. Source checks read web/src and the
bundle; the runtime tests drive the built bundle in headless Chromium against the fake server
of tests/test_ha_ui.py, in both layouts, as an active instance and as a standby, in English
and German. They skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _classes,  # noqa: F401
                        _wait_for_call, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')

KEYS = ['cephOsdLatencyTitle', 'cephOsdLatencyHelp', 'cephOsdLatencyLimit', 'cephOsdLatencySummary',
        'replicationRpoTitle', 'replicationRpoHelp', 'replicationRpoLimit', 'replicationRpoAutoHint',
        'replicationRpoSummary', 'replicationRpoSummaryAuto']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _added_blocks():
    dash = _read('web', 'src', 'dashboard.js')
    return [
        _between(dash, "{/* LW Oct 2026 - an OSD limit in ms", "{alertMetricSel !== 'rolling_update' && ("),
        _between(dash, "if (alert.metric === 'ceph_osd_latency')", 'return `${alert.metric?.toUpperCase()}'),
        _between(dash, '<option value="ceph_osd_latency">', '<option value="snapshot_age">'),
        _between(dash, ": alertMetricSel === 'ceph_osd_latency' ? t('cephOsdLatencyHelp')", ': t(\'alertSnapHelp\')'),
    ]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used():
    src = _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('((?:cephOsdLatency|replicationRpo)[A-Za-z]*)'\)", src))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key in ('cephOsdLatencySummary', 'replicationRpoSummary'):
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9 and all('{n}' in v for v in values), (key, values)
    # the automatic one has nothing to fill in
    values = re.findall(r'^\s*replicationRpoSummaryAuto: "(.*)",$', tr, re.M)
    assert len(values) == 9 and not any('{' in v for v in values)


def test_the_keys_sit_with_the_other_alert_rules_and_the_german_block_keeps_its_flag():
    tr = _read('web', 'src', 'translations.js')
    assert tr.index('            de: {') < tr.index('cephOsdLatencyTitle: "Ceph-OSD-Latenz"') < tr.index('            en: {')
    blocks = re.split(r'^            [a-z]{2}: \{$', tr, flags=re.M)[1:]
    assert len(blocks) == 9
    for block in blocks:
        lines = [ln.strip().split(':', 1)[0] for ln in block.splitlines()]
        at = lines.index('qdeviceAlertSummary')
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


def test_an_osd_rule_offers_no_guest_and_an_rpo_rule_no_node():
    dash = _read('web', 'src', 'dashboard.js')
    assert "{alertMetricSel !== 'replication_rpo' && <option value=\"node\">" in dash
    assert ("{alertMetricSel !== 'ceph_osd_latency' && alertMetricSel !== 'zfs_health' && "
            "alertMetricSel !== 'clock_drift' && alertMetricSel !== 'qdevice' && <option value=\"vm\">") in dash
    assert ("['task_failed', 'ceph_health', 'ceph_osd_latency', 'replication', 'replication_rpo', 'snapshot_age', "
            "'backup_coverage', 'zfs_health', 'clock_drift', 'restart_loop', 'qdevice'];") in dash


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('React.createElement("option",{value:"ceph_osd_latency"}',
                   'React.createElement("option",{value:"replication_rpo"}',
                   'data-event-fields":"replication_rpo"', 'data-event-fields":"ceph_osd_latency"',
                   'replicationRpoSummaryAuto', 'cephOsdLatencySummary'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

OSD_RULE = {'id': 'o1', 'name': 'OSDs', 'cluster_id': 'c1', 'metric': 'ceph_osd_latency', 'operator': 'event',
            'threshold': 100, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
            'notify_resolved': True, 'severity': 'auto'}
RPO_RULE = {'id': 'p1', 'name': 'RPO', 'cluster_id': 'c1', 'metric': 'replication_rpo', 'operator': 'event',
            'threshold': 0, 'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True,
            'notify_resolved': True, 'severity': 'auto'}
RPO_RULE_SET = dict(RPO_RULE, id='p2', name='RPO 100', threshold=240, target_type='vm', target_id='100')
OSD_INCIDENT = {'id': 'i5', 'alert_id': 'o1', 'severity': 'warning', 'metric': 'ceph_osd_latency', 'operator': 'event',
                'message': 'osd.3 on node pve1: apply latency 250 ms, commit latency 310 ms, above 100 ms in each '
                           'of the last 3 reads',
                'target_type': 'node', 'target_name': 'pve1', 'current_value': 310, 'threshold': 100,
                'triggered_at': '2026-10-09T01:00:00', 'last_fired_at': '2026-10-09T01:00:00', 'acked_at': None,
                'acked_by': None, 'escalation_step': 0, 'object_key': 'osd:pve1:3', 'muted_until': None}
RPO_INCIDENT = {'id': 'i6', 'alert_id': 'p1', 'severity': 'critical', 'metric': 'replication_rpo', 'operator': 'event',
                'message': 'Replication job j1 (web01 (100) from Testi to DR) last ran successfully 26 h ago; '
                           'the RPO is 12 h.',
                'target_type': 'vm', 'target_name': 'web01 (100)', 'current_value': 1560, 'threshold': 0,
                'triggered_at': '2026-10-09T01:05:00', 'last_fired_at': '2026-10-09T01:05:00', 'acked_at': None,
                'acked_by': None, 'escalation_step': 0, 'object_key': 'xcrepl:100:j1', 'muted_until': None}
ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [OSD_RULE, RPO_RULE, RPO_RULE_SET]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': [OSD_INCIDENT, RPO_INCIDENT]}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/o1'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/p2'): (200, {'success': True, 'alert': {}}),
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
    page.locator('[data-alert-rule="p1"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _new_rule(page, metric):
    page.locator('button', has_text='New Alert').first.click()
    sel = page.locator('select[name="metric"]')
    sel.wait_for(timeout=3000)
    sel.select_option(metric)
    page.locator(f'[data-event-fields="{metric}"]').wait_for(timeout=3000)
    return page.locator(f'[data-event-fields="{metric}"]')


def _targets(page):
    return page.locator('select[name="target_type"] option').evaluate_all('o => o.map(x => x.value)')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_rules_and_their_incidents_in_the_list(open_app, layout):
    app = open_app(layout=layout)
    page = _to_alerts(app, layout)
    assert 'OSD latency above 100 ms' in page.locator('[data-alert-rule="o1"]').inner_text()
    assert 'Last successful run more than twice the interval ago' in page.locator('[data-alert-rule="p1"]').inner_text()
    assert 'Last successful run more than 240 min ago' in page.locator('[data-alert-rule="p2"]').inner_text()
    assert 'commit latency 310 ms' in page.locator('[data-active-alert="i5"]').inner_text()
    assert 'the RPO is 12 h' in page.locator('[data-active-alert="i6"]').inner_text()
    # an OSD incident is muted for its node, a replication for its guest
    page.locator('[data-active-alert="i5"] button[title="Mute"]').click()
    assert 'every rule for pve1' in page.locator('[data-mute-menu]').inner_text()
    page.locator('[data-active-alert="i6"] button[title="Mute"]').click()
    assert 'every rule for web01 (100)' in page.locator('[data-mute-menu]').inner_text()
    _shot(page, f'{layout}_alerts_osd_rpo.png')
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_an_osd_rule_needs(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    fields = _new_rule(page, 'ceph_osd_latency')
    assert fields.locator('input[name="threshold"]').input_value() == '100'
    assert 'three reads in a row' in page.locator('[data-event-help]').inner_text()
    # an OSD sits on a node: the cluster or one node, never a guest
    assert _targets(page) == ['cluster', 'node']
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('input[name="notify_resolved"]').is_checked()
    page.locator('input[name="name"]').fill('Slow OSDs on pve1')
    page.locator('select[name="target_type"]').select_option('node')
    page.locator('input[name="target_id"]').fill('pve1')
    fields.locator('input[name="threshold"]').fill('40')
    _shot(page, 'modern_alerts_dialog_osd.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'name': 'Slow OSDs on pve1', 'metric': 'ceph_osd_latency', 'operator': 'event', 'threshold': 40,
                 'target_type': 'node', 'target_id': 'pve1', 'notify_resolved': True}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_an_rpo_rule_needs(open_app):
    app = open_app(layout='corporate')
    page = _to_alerts(app, 'corporate')
    fields = _new_rule(page, 'replication_rpo')
    assert fields.locator('input[name="threshold"]').input_value() == '0'
    assert 'twice its interval' in fields.inner_text()
    assert 'Site Recovery plans' in page.locator('[data-event-help]').inner_text()
    # a job belongs to its guest: the cluster or one guest, never a node
    assert _targets(page) == ['cluster', 'vm']
    page.locator('input[name="name"]').fill('RPO of 100')
    page.locator('select[name="target_type"]').select_option('vm')
    page.locator('input[name="target_id"]').fill('100')
    fields.locator('input[name="threshold"]').fill('240')
    _shot(page, 'corporate_alerts_dialog_rpo.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'metric': 'replication_rpo', 'operator': 'event', 'threshold': 240,
                 'target_type': 'vm', 'target_id': '100'}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors


def test_runtime_an_automatic_rpo_is_sent_as_zero(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    _new_rule(page, 'replication_rpo')
    page.locator('input[name="name"]').fill('RPO')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    assert (body['metric'], body['threshold'], body['target_type']) == ('replication_rpo', 0, 'cluster')
    assert not app.errors, app.errors


def test_runtime_editing_keeps_what_was_saved(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    page.locator('[data-alert-rule="p2"] button[title="Edit Alert"]').click()
    fields = page.locator('[data-event-fields="replication_rpo"]')
    fields.wait_for(timeout=3000)
    assert fields.locator('input[name="threshold"]').input_value() == '240'
    assert page.locator('select[name="target_type"]').input_value() == 'vm'
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/alerts/p2'))
    body = app.server.bodies['/api/clusters/c1/alerts/p2'][-1]
    assert (body['threshold'], body['target_type'], body['target_id']) == (240, 'vm', '100')

    page.locator('[data-alert-rule="o1"] button[title="Edit Alert"]').click()
    page.locator('[data-event-fields="ceph_osd_latency"]').wait_for(timeout=3000)
    assert page.locator('[data-event-fields="ceph_osd_latency"] input[name="threshold"]').input_value() == '100'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_them_and_offers_no_change(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _to_alerts(app, layout)
    assert 'OSD latency above 100 ms' in page.locator('[data-alert-rule="o1"]').inner_text()
    assert page.locator('[data-active-alert="i6"]').count() == 1
    assert page.locator('button', has_text='New Alert').count() == 0
    assert page.locator('[data-alert-rule="p1"] button[title="Edit Alert"]').count() == 0
    assert page.locator('[data-active-alert="i5"] button[title="Mute"]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/alert' in c[1]]
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = _to_alerts(app)
    assert 'OSD-Latenz über 100 ms' in page.locator('[data-alert-rule="o1"]').inner_text()
    assert 'Letzter erfolgreicher Lauf vor mehr als 240 Min.' in page.locator('[data-alert-rule="p2"]').inner_text()
    page.locator('button', has_text=re.compile(r'Neuer Alarm|New Alert')).first.click()
    sel = page.locator('select[name="metric"]')
    sel.wait_for(timeout=3000)
    labels = sel.locator('option').all_inner_texts()
    assert 'Ceph-OSD-Latenz' in labels and 'Replikation über ihrem RPO (PegaProx-Jobs)' in labels
    sel.select_option('replication_rpo')
    fields = page.locator('[data-event-fields="replication_rpo"]')
    assert 'RPO (Minuten)' in fields.inner_text() and 'Doppelte seines Intervalls' in fields.inner_text()
    _shot(page, 'modern_alerts_dialog_rpo_de.png')
    assert not app.errors, app.errors
