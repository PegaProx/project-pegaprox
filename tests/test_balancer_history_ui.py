"""The balancer history and its cooldown in the cluster settings.

Under the balancing settings sits the list of what the balancer moved and why
(GET /api/clusters/<id>/balance-history): newest first, filtered by reason and outcome,
a page at a time, worded in the reader's language from the numbers the server stored. The
cooldown between two moves of one guest is a slider in minutes next to the check interval;
a standby that does not hand writes on shows it locked. The overview's last migrations
name which rule of the balancer moved a guest.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import (CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, _blocks, _classes,  # noqa: F401
                        browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS = ['balCooldown', 'balCooldownDesc', 'balCooldownUnit', 'balCooldownHours', 'balHistTitle', 'balHistDesc',
        'balHistFilterTrigger', 'balHistFilterStatus', 'balHistAllTriggers', 'balHistAllOutcomes',
        'balHistTriggerBalance', 'balHistTriggerPredictive', 'balHistTriggerAffinity', 'balHistTriggerPin',
        'balHistStatusSuccess', 'balHistStatusFailed', 'balHistStatusDryRun', 'balHistNone', 'balHistNoMatch',
        'balHistLoadMore', 'balHistLoadError', 'balHistWhyBalance', 'balHistWhyPredictive',
        'balHistWhyAffinity', 'balHistWhyPin', 'balHistManual', 'balHistRerouted', 'balHistFailedWith']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 - what the balancer moved on this cluster and why')
    return src[start:src.index('// NS May 2026', start)]


def _settings_blocks():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('{/* LW Oct 2026 - the pause before the balancer moves the same guest again')
    slider = src[start:src.index('</fieldset>', start)]
    start = src.index('{/* LW Oct 2026 - the balancer\'s moves with why, under its settings */}')
    card = src[start:src.index('{/* Update Manager Section */}', start)]
    return slider + card


def _overview_block():
    src = _read('web', 'src', 'vm_modals.js')
    start = src.index('// LW Oct 2026 - which rule of the balancer moved a guest')
    return src[start:src.index('// #621 (ccesario)', start)]


def _all():
    return _component() + _settings_blocks() + _overview_block()


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_the_keys_sit_with_the_balancing_settings():
    for lang, block in _blocks().items():
        lines = block.splitlines()
        at = next(i for i, line in enumerate(lines) if re.match(r'^ +migrationToleranceDesc:', line))
        assert [re.match(r'^ +(\w+):', line).group(1) for line in lines[at + 1:at + 1 + len(KEYS)]] == KEYS, lang


def test_every_new_key_is_used_and_nothing_else_is_new():
    used = set(re.findall(r"'(bal(?:Hist|Cooldown)\w*)'", _all()))
    assert used == set(KEYS)


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in KEYS:
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_dash_in_what_this_change_added():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_all()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_all())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', _all()))
    assert used
    for name in used:
        assert re.search(r'^ +%s: \(' % name, icons, re.M), name


def test_the_cooldown_is_locked_on_a_standby_and_sent_in_seconds():
    block = _settings_blocks()
    assert "<fieldset disabled={haReadOnly || !can('cluster.config')}" in block
    assert "data-ha-locked={haReadOnly ? '' : undefined}" in block
    assert "updateConfig('migration_cooldown', Number(e.target.value) * 60)" in block


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function BalancerHistory(', '/balance-history?', 'data-bal-cooldown', 'balHistWhyBalance',
                   'data-mig-trigger'):
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

HIST = '/api/clusters/c1/balance-history'
PAGE = 3
BAL_CLUSTER = dict(CLUSTER, auto_migrate=True, dry_run=False, migration_threshold=20, migration_tolerance=10,
                   check_interval=300, migration_cooldown=900)


def _row(rid, vmid, name, trigger, status, details, reason='x'):
    return {'id': rid, 'vmid': vmid, 'vm_name': name, 'source_node': details.get('source', 'pve1'),
            'target_node': details.get('target', 'pve2'), 'trigger': trigger, 'status': status,
            'reason': reason, 'details': details, 'duration': 12.5, 'timestamp': '2026-10-07T10:00:00+02:00'}


ROWS = [
    _row(6, 101, 'web01', 'balance', 'success', {
        'source': 'pve1', 'target': 'pve2', 'source_load': {'score': 80.0, 'cpu': 70.0, 'mem': 90.0},
        'target_load': {'score': 20.0, 'cpu': 10.0, 'mem': 30.0}, 'diff': 60.0, 'threshold': 20.0,
        'tolerance': 10.0, 'manual': True}),
    _row(5, 102, 'db01', 'predictive', 'success', {
        'source': 'pve1', 'target': 'pve2', 'forecast': 88.4, 'confidence': 75, 'threshold': 75.0,
        'target_load': {'score': 30.0, 'cpu': 15.0, 'mem': 25.0}}),
    _row(4, 103, 'app01', 'affinity', 'failed', {
        'source': 'pve1', 'target': 'pve3', 'rule': 'web apart', 'error': 'Task failed'}),
    _row(3, 104, 'gpu01', 'pin', 'dry_run', {'source': 'pve1', 'target': 'pve3', 'pinned': ['pve3']}),
    _row(2, 105, 'ha01', 'balance', 'success', {
        'source': 'pve2', 'target': 'pve3', 'source_load': {'score': 70.0, 'cpu': 1, 'mem': 2},
        'target_load': {'score': 30.0, 'cpu': 3, 'mem': 4}, 'diff': 40.0, 'threshold': 20.0,
        'tolerance': 10.0, 'requested_target': 'pve1'}),
    _row(1, 106, 'mine01', 'balance', 'success', {}, reason=''),
]


class _HistServer(_FakeServer):
    """The history route as the server pages it: filtered, newest first, PAGE rows at a time."""

    rows = ROWS

    def handle(self, route):
        req = route.request
        parsed = urlparse(req.url)
        if parsed.path == HIST and ('GET', HIST) not in self.fixed:
            q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            rows = [r for r in self.rows
                    if (not q.get('trigger') or r['trigger'] in q['trigger'].split(','))
                    and (not q.get('status') or r['status'] == q['status'])
                    and (not q.get('before') or r['id'] < int(q['before']))]
            page = rows[:PAGE]
            self.extra[('GET', HIST)] = (200, {'entries': page, 'cooldown': 900,
                                               'next_before': page[-1]['id'] if len(rows) > PAGE else None})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(cluster=None, rows=None, **kw):
        extra = dict(SSE_TOKEN)
        extra[('PATCH', '/api/clusters/c1/config')] = (200, {'message': 'ok'})
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        server = _HistServer(clusters=[cluster or BAL_CLUSTER], resources=[VM], extra=extra, **kw)
        server.fixed = set(extra)
        if rows is not None:
            server.rows = rows
        app = _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _wait_for(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _open_settings(app, tab='Settings'):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name=tab, exact=True).first.click()
    page.get_by_text('Automatic Migration' if tab == 'Settings' else 'Testi').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _reads(app):
    return [u for u in app.server.urls if urlparse(u).path == HIST]


def _row_text(page, rid):
    return page.locator(f'[data-bal-row="{rid}"]').inner_text()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_moves_show_with_why(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    assert page.locator('[data-balancer-history] h3').inner_text().strip() == 'Balancer History'
    assert page.locator('[data-bal-row]').count() == 3
    six = _row_text(page, 6)
    assert 'web01 (101)' in six and 'Load imbalance' in six and 'Moved' in six
    assert ('pve1 at score 80 (CPU 70%, RAM 90%) and pve2 at 20 (CPU 10%, RAM 30%) were 60 apart, more '
            'than the threshold 20 plus the tolerance 10. Started by hand.') in six
    five = _row_text(page, 5)
    assert 'Load trend' in five
    assert ('pve1 was heading for overload (forecast score 88.4, above 75, confidence 75%), so the guest '
            'went to the least loaded node pve2 (score 30).') in five
    four = _row_text(page, 4)
    assert 'Anti-affinity rule' in four and 'Failed' in four
    assert ('The anti-affinity rule "web apart" keeps its guests apart and another of them ran on pve1, so '
            'this one went to pve3. Error: Task failed') in four
    assert page.locator('[data-bal-row="6"] [data-bal-status="success"]').count() == 1
    # one read on opening, no polling
    page.wait_for_timeout(2500)
    assert len(_reads(app)) == 1
    assert 'limit=50' in _reads(app)[0]
    assert not app.errors, app.errors


def test_runtime_older_moves_come_a_page_at_a_time(open_app):
    app = open_app(layout='modern')
    page = _open_settings(app)
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    page.locator('[data-bal-more]').click()
    page.locator('[data-bal-row="3"]').wait_for(timeout=5000)
    assert 'before=4' in _reads(app)[-1]
    assert page.locator('[data-bal-row]').count() == 6
    assert 'Pinned to pve3 but running on pve1, so it went back to pve3.' in _row_text(page, 3)
    assert 'Dry run only' in _row_text(page, 3)
    assert 'Proxmox HA placed it on pve3 instead of pve1.' in _row_text(page, 2)
    # a confined caller's row carries no numbers: no reason line, nothing made up
    assert page.locator('[data-bal-row="1"] [data-bal-why]').count() == 0
    assert page.locator('[data-bal-more]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_filters_ask_the_server(open_app):
    app = open_app(layout='modern')
    page = _open_settings(app)
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    page.locator('[data-bal-filter-trigger]').select_option('affinity')
    assert _wait_for(page, lambda: 'trigger=affinity' in _reads(app)[-1])
    page.locator('[data-bal-row="6"]').wait_for(state='detached', timeout=5000)
    assert page.locator('[data-bal-row]').count() == 1 and page.locator('[data-bal-row="4"]').count() == 1
    page.locator('[data-bal-filter-status]').select_option('success')
    assert _wait_for(page, lambda: 'status=success' in _reads(app)[-1])
    page.locator('[data-bal-empty]').wait_for(timeout=5000)
    assert page.locator('[data-bal-empty]').inner_text().strip() == 'No move matches this filter.'
    assert not app.errors, app.errors


def test_runtime_nothing_moved_yet(open_app):
    app = open_app(layout='modern', rows=[])
    page = _open_settings(app)
    page.locator('[data-bal-empty]').wait_for(timeout=5000)
    assert page.locator('[data-bal-empty]').inner_text().strip() == \
        'The balancer has not moved a guest on this cluster yet.'
    assert not app.errors, app.errors


def test_runtime_a_leader_that_does_not_answer_is_named(open_app):
    away = {'error': 'The active instance does not answer', 'code': 'HA_ACTIVE_UNREACHABLE'}
    app = open_app(layout='modern', extra={('GET', HIST): (503, away)})
    page = _open_settings(app)
    page.locator('[data-bal-leader-away]').wait_for(timeout=5000)
    assert 'Only the leader' in page.locator('[data-bal-leader-away]').inner_text()
    assert page.locator('[data-balancer-history]').get_by_text('could not be loaded').count() == 0
    assert not app.errors, app.errors


def _choices(page):
    return [o.strip() for o in page.locator('#bal-cooldown option').all_inner_texts()]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_cooldown_is_set_in_minutes_and_saved_in_seconds(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    box = page.locator('[data-bal-cooldown]')
    box.wait_for(timeout=5000)
    assert 'Cooldown Between Moves' in box.inner_text()
    select = page.locator('#bal-cooldown')
    assert select.is_enabled() and select.input_value() == '15'
    assert _choices(page) == ['1\u00a0min', '5\u00a0min', '10\u00a0min', '15\u00a0min', '30\u00a0min', '1\u00a0h',
                              '2\u00a0h', '4\u00a0h', '8\u00a0h', '12\u00a0h', '24\u00a0h']
    select.select_option('120')
    assert _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c1/config'))
    assert app.server.bodies['/api/clusters/c1/config'][-1] == {'migration_cooldown': 7200}
    assert select.input_value() == '120'
    assert page.locator('fieldset[data-ha-locked][data-bal-cooldown]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_cooldown_set_over_the_api_is_shown_as_it_is(open_app):
    app = open_app(layout='modern', cluster=dict(BAL_CLUSTER, migration_cooldown=2700))
    page = _open_settings(app)
    select = page.locator('#bal-cooldown')
    select.wait_for(timeout=5000)
    assert select.input_value() == '45'
    assert _choices(page)[4:7] == ['30\u00a0min', '45\u00a0min', '1\u00a0h']
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_the_cooldown_locked_and_still_reads_the_history(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _open_settings(app)
    page.locator('[data-bal-cooldown]').wait_for(timeout=5000)
    assert page.locator('fieldset[data-ha-locked][data-bal-cooldown]').count() == 1
    assert page.evaluate('() => document.querySelector("[data-bal-cooldown]").disabled')
    select = page.locator('#bal-cooldown')
    assert not select.is_enabled()
    try:
        select.select_option('60', force=True, timeout=1500)
    except Exception:
        pass    # a disabled select takes no choice
    page.wait_for_timeout(900)
    assert '/api/clusters/c1/config' not in app.server.bodies
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_without_cluster_config_the_cooldown_only_shows(open_app):
    app = open_app(layout='modern', admin=False, permissions=['cluster.view'])
    page = _open_settings(app)
    page.locator('[data-bal-cooldown]').wait_for(timeout=5000)
    assert not page.locator('#bal-cooldown').is_enabled()
    # cluster.view is what the history wants
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Einstellungen', exact=True).first.click()
    page.locator('[data-bal-row="6"]').wait_for(timeout=5000)
    assert page.locator('[data-balancer-history] h3').inner_text().strip() == 'Balancer-Verlauf'
    six = _row_text(page, 6)
    assert 'Ungleiche Last' in six and 'Verschoben' in six and 'Von Hand gestartet.' in six
    assert 'pve1 mit Score 80 (CPU 70%, RAM 90%)' in six
    assert 'Pause zwischen Verschiebungen' in page.locator('[data-bal-cooldown]').inner_text()
    assert _choices(page)[-1] == '24\u00a0Std.'
    assert 'balHist' not in page.locator('[data-balancer-history]').inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_last_migrations_name_the_balancer_rule(open_app, layout):
    log = [{'timestamp': '2026-10-07T10:00:00', 'vm': 'web01', 'vmid': 100, 'from_node': 'pve1',
            'to_node': 'pve2', 'dry_run': False, 'success': True, 'trigger': 'affinity'},
           {'timestamp': '2026-10-07T11:00:00', 'vm': 'db01', 'vmid': 101, 'from_node': 'pve2',
            'to_node': 'pve1', 'dry_run': False, 'success': True}]
    app = open_app(layout=layout, extra={('GET', '/api/clusters/c1/migrations'): (200, log)})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('[data-mig-trigger="affinity"]').wait_for(timeout=8000)
    assert page.locator('[data-mig-trigger]').count() == 1
    assert page.locator('[data-mig-trigger="affinity"]').inner_text().strip() == 'Anti-affinity rule'
    assert not app.errors, app.errors
