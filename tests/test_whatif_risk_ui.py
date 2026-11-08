"""The risk view in the web UI: critical badges, tenant and restore columns, the PBS scenario in
the picker and the Ranking view (web/src/dashboard.js WhatIfTab).

The reports come from the real engine on a small cluster, so the view is tested against the
shape the routes send. Runtime tests drive the built bundle in headless Chromium against the
fake server of tests/test_ha_ui.py and skip where Playwright is not installed.
LW Oct 2026
"""
import json
import re
import time
import types

import pytest

from pegaprox.core import recovery, whatif
from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _read, browser)  # noqa: F401
from test_whatif import NETS, THR, _cfg, _cluster, _manager, _vm
from test_whatif_risk import T_PBS, _pve

URL = '/api/clusters/c1/whatif'
RANK = URL + '/ranking'
NOW = time.time()


# -- source ------------------------------------------------------------------------------------

def test_the_new_view_code_is_in_the_bundle():
    bundle = _read('web', 'index.html')
    for needle in ('whatif/ranking', 'data-whatif-view', 'whatifRankRun', 'whatifPbsFailure', 'whatifColRestore'):
        assert needle in bundle, needle


def test_the_scenario_list_has_the_pbs_scenario_and_the_tables_know_its_codes():
    dash = _read('web', 'src', 'dashboard.js')
    assert "id: 'pbs_failure'" in dash
    for code in ('pbs_only_copy', 'pbs_some_copy', 'pbs_job_only', 'pbs_tests_lost', 'rank_weighting'):
        assert f'{code}: ' in dash


# -- the reports the view is shown ---------------------------------------------------------------

@pytest.fixture
def risk_data(monkeypatch):
    """Marks and tenants the engine reads, set for one test."""
    marks = {
        100: {'vmid': 100, 'last_at': NOW - 60, 'last_result': 'passed', 'ok_at': NOW - 60, 'ok_backup_ts': T_PBS,
              'ok_seconds': 30.0, 'ok_checks': []},
        101: {'vmid': 101, 'last_at': NOW - 30, 'last_result': 'failed', 'fail_at': NOW - 30, 'fail_cause': 'x'},
    }
    monkeypatch.setattr(whatif, '_marks', lambda cid: marks)
    monkeypatch.setattr(whatif, '_tenants', lambda cid: [{'id': 'acme', 'name': 'Acme Corp'}])
    recovery.forget_backups()
    yield
    recovery.forget_backups()


def _node_report():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve2')]
    guests[0]['tags'] = 'critical;web'
    m = _manager(_cluster(guests, {100: _cfg(), 101: _cfg(), 102: _cfg()}, ha=[('vm:100', 'started')], extra=NETS),
                 guests)
    out = whatif.run(m, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    return dict(json.loads(json.dumps(out)), guests_hidden=0, guests_truncated=0)


def _pbs_cluster():
    guests, pve = _pve(tags={100: 'critical', 101: 'db'},
                       jobs=[{'id': 'job-a', 'storage': 'pbs1', 'all': 1, 'exclude': '103', 'schedule': '01:00'}])
    return _manager(pve, guests)


def _pbs_report():
    out = whatif.run(_pbs_cluster(), whatif.parse_scenario({'type': 'pbs_failure', 'storage': 'pbs1'}), dict(THR))
    return dict(json.loads(json.dumps(out)), guests_hidden=0, guests_truncated=0)


def _pbs_offline_report():
    """The storage is listed as not available and its content cannot be read."""
    guests, pve = _pve(tags={100: 'critical', 101: 'db'},
                       jobs=[{'id': 'job-a', 'storage': 'pbs1', 'all': 1, 'exclude': '103', 'schedule': '01:00'}])
    pve[('/cluster/resources', 'storage')] = [x for x in pve[('/cluster/resources', 'storage')]
                                              if x['storage'] != 'pbs1']
    pve[('/nodes/pve1/storage/pbs1/content', 'backup')] = types.SimpleNamespace(status_code=500, json=lambda: {}, text='')
    recovery.forget_backups()
    out = whatif.run(_manager(pve, guests), whatif.parse_scenario({'type': 'pbs_failure', 'storage': 'pbs1'}),
                     dict(THR))
    return dict(json.loads(json.dumps(out)), guests_hidden=0, guests_truncated=0)


def _stopped_report():
    guests = [_vm(100, 'pve1', status='stopped'), _vm(101, 'pve1', status='stopped'),
              _vm(102, 'pve2', status='stopped')]
    m = _manager(_cluster(guests, {v['vmid']: _cfg() for v in guests}, ha=[('vm:100', 'started')], extra=NETS),
                 guests)
    out = whatif.run(m, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    return dict(json.loads(json.dumps(out)), guests_hidden=0, guests_truncated=0)


def _options():
    out = json.loads(json.dumps(whatif.options(_pbs_cluster())))
    out['thresholds'] = {'cpu': 80.0, 'memory': 90.0, 'cpu_source': 'default', 'memory_source': 'default'}
    return out


def _ranking(status='running'):
    return json.loads(json.dumps(whatif.ranking(_rank_env_manager(status), dict(THR))))


def _rank_env_manager(status='running'):
    guests = [_vm(100, 'pve1', status=status), _vm(101, 'pve1', status=status), _vm(102, 'pve2', status=status)]
    guests[1]['tags'] = 'critical'
    api = _cluster(guests, {100: _cfg(), 101: _cfg(), 102: _cfg(bridge='vmbr1')}, ha=[('vm:100', 'started')], extra=NETS)
    api[('/nodes/pve1/storage/ceph/content', 'images')] = [{'vmid': 100}, {'vmid': 101}, {'vmid': 102}]
    api[('/nodes/pve1/storage/ceph/content', 'rootdir')] = []
    return _manager(api, guests)


@pytest.fixture
def open_risk(browser):  # noqa: F811
    apps = []

    def _open(layout='modern', language='en', options=None, report=None, ranking=None, rank_status=200):
        extra = dict(SSE_TOKEN)
        extra[('GET', '/api/clusters/c1/reports/summary')] = (200, {'period': 'day', 'data_points': 0, 'timestamps': []})
        extra[('GET', '/api/clusters/c1/reports/top-vms')] = (200, [])
        extra[('GET', URL + '/options')] = (200, options or _options())
        extra[('POST', URL)] = (200, report or _node_report())
        extra[('POST', RANK)] = (rank_status, ranking or _ranking())
        app = _App(browser, _FakeServer(role='standalone', layout=layout, language=language, clusters=[CLUSTER],
                                        resources=[VM], metrics=NODE_METRICS, extra=extra))
        apps.append(app)
        page = app.page
        label = 'Was-wäre-wenn' if language == 'de' else 'What-if'
        if layout == 'cloud':
            page.locator('.cloud-shell').get_by_text(label, exact=True).first.click()
        else:
            page.get_by_text('Testi').first.click()
            page.wait_for_timeout(500)
            page.locator('body').click(position={'x': 5, 'y': 400})
            page.keyboard.press('g')
            page.keyboard.press('p')
            page.locator('button', has_text=label).first.click()
        page.locator('[data-whatif="picker"] [data-whatif-scenario]').first.wait_for(timeout=10000)
        page.locator('[data-whatif-node], [data-whatif-field]').first.wait_for(timeout=10000)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _posted(app, path=URL):
    return app.server.bodies.get(path, [])


# -- runtime ------------------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_critical_badges_tenants_and_restore_status(open_risk, risk_data, layout):
    app = open_risk(layout)
    page = app.page
    page.locator('[data-whatif-node="pve1"]').check()
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert _posted(app)[-1] == {'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1']}
    row100, row101 = page.locator('[data-whatif-guest="100"]'), page.locator('[data-whatif-guest="101"]')
    assert row100.locator('[data-whatif-critical]').count() == 1 and row101.locator('[data-whatif-critical]').count() == 0
    assert row100.locator('[data-whatif-restore="proven"]').inner_text() == 'Proven'
    assert row101.locator('[data-whatif-restore="failing"]').inner_text() == 'Failing'
    assert 'Acme Corp' in row100.locator('[data-whatif-tenants]').inner_text()
    assert row100.locator('[data-whatif-restore="proven"] + [data-whatif-basis="known"]').count() == 1
    risk = page.locator('[data-whatif="risk"]')
    assert 'Critical guests affected: 1 of 1, down: 0' in risk.locator('[data-whatif-risk="critical"]').inner_text()
    assert 'critical (default)' not in risk.inner_text() and 'default' in risk.locator('[data-whatif-risk="critical"]').inner_text()
    assert risk.locator('[data-whatif-restore-count="proven"]').inner_text() == 'Proven: 1'
    assert risk.locator('[data-whatif-restore-count="failing"]').inner_text() == 'Failing: 1'
    assert 'Acme Corp: 2 affected, 1 down, 1 critical' in risk.locator('[data-whatif-tenant="acme"]').inner_text()
    assert 'Weight of the affected guests: 1.75' in risk.locator('[data-whatif-risk="weight"]').inner_text()
    # every new statement carries its basis
    assert risk.locator('[data-whatif-basis]').count() >= 5
    assert page.locator('[data-whatif-assumption="tenant_by_cluster"]').is_visible()
    assert not app.errors, app.errors


def test_runtime_the_critical_tags_are_sent_only_when_changed(open_risk, risk_data):
    app = open_risk('modern')
    page = app.page
    field = page.locator('[data-whatif="picker"] [data-whatif-field="tags"]')
    assert field.input_value() == 'critical'
    page.locator('[data-whatif-node="pve1"]').check()
    field.fill('db, Prod')
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert _posted(app)[-1]['critical_tags'] == ['db', 'prod']
    assert not app.errors, app.errors


def test_runtime_the_pbs_scenario_in_the_picker(open_risk, risk_data):
    app = open_risk('corporate', report=_pbs_report())
    page = app.page
    page.locator('[data-whatif-scenario="pbs_failure"]').click()
    assert page.locator('[data-whatif="run"]').is_disabled()
    assert page.get_by_text('Pick a backup storage.').is_visible()
    assert page.locator('[data-whatif-field="pbs"] option').all_inner_texts() == ['-', 'backups', 'pbs1']
    page.locator('[data-whatif-field="pbs"]').select_option('pbs1')
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="pbs"]').wait_for(timeout=5000)
    assert _posted(app)[-1] == {'type': 'pbs_failure', 'memory': 'configured', 'storage': 'pbs1'}
    card = page.locator('[data-whatif="pbs"]').inner_text()
    assert 'Backup storage pbs1' in card and 'Job job-a (01:00): 4 guests' in card
    assert 'Every listed restore point lost: 1. Some lost: 1. Covered by a job, none listed: 2.' in card
    assert 'Restore tests that rested on it: 1.' in card
    row = page.locator('[data-whatif-guest="100"]')
    assert 'every restore point of it listed is on pbs1' in row.inner_text()
    assert 'its restore test used a restore point on this storage' in row.inner_text()
    assert row.locator('[data-whatif-critical]').count() == 1
    assert page.locator('[data-whatif-limit="pbs_tests_lost"]').inner_text().startswith(
        'Guests whose proven restore test used a restore point on it: 1')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_ranking_view(open_risk, layout):
    app = open_risk(layout)
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    assert page.locator('[data-whatif="picker"]').count() == 0
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    assert _posted(app, RANK)[-1] == {}       # the cluster's own critical tags are not re-sent
    rows = page.locator('[data-whatif-rank-row]')
    order = [r.get_attribute('data-whatif-rank-row') for r in rows.all()]
    assert order[:3] == ['storage:ceph', 'bridge:vmbr0', 'node:pve1'], order
    weights = {r.get_attribute('data-whatif-rank-row'): r.locator('[data-whatif-rank-weight]').inner_text() for r in rows.all()}
    assert weights['storage:ceph'] == '5' and weights['bridge:vmbr0'] == '4' and weights['node:pve1'] == '3.25'
    assert 'Weighting: down 1, degraded or unknown 0.5, restarted 0.25, moved 0; a critical guest counts 3 times that.' \
        in page.locator('[data-whatif="rank-weighting"]').inner_text()
    assert page.locator('[data-whatif-rank-row="storage:ceph"] [data-whatif-basis="calculated"]').count() == 1
    assert page.locator('[data-whatif="rank-assumptions"] [data-whatif-assumption="rank_cheap"]').is_visible()
    # changed tags are sent
    page.locator('[data-whatif="rank-picker"] [data-whatif-field="tags"]').fill('prod')
    page.locator('[data-whatif="rank-run"]').click()
    page.wait_for_timeout(300)
    assert _posted(app, RANK)[-1] == {'critical_tags': ['prod']}
    # back to the scenario
    page.locator('[data-whatif-view="scenario"]').click()
    page.locator('[data-whatif="picker"]').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_the_ranking_says_what_was_capped_left_out_and_stopped(open_risk):
    data = _ranking()
    data['capped'] = [{'kind': 'node', 'cap': 100, 'total': 130}]
    data['skipped'] = [{'kind': 'bridge', 'name': 'vmbr9', 'code': 'unknown_bridge'}]
    data['stopped'] = {'ranked': 6, 'left': 2}
    data['configs_unread'] = 40
    app = open_risk('modern', ranking=data)
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    assert page.locator('[data-whatif-rank-capped="node"]').inner_text() == 'Capped: Node, 100 of 130 ranked.'
    assert 'vmbr9 (unknown_bridge)' in page.locator('[data-whatif="rank-skipped"]').inner_text()
    assert page.locator('[data-whatif="rank-stopped"]').inner_text() == 'Stopped at the time limit: 6 run, 2 not run.'
    assert 'Guest configurations not read: 40' in page.locator('[data-whatif="rank"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_a_refused_ranking_shows_the_error(open_risk):
    app = open_risk('modern', ranking={'error': 'Access denied: this action affects the whole cluster'}, rank_status=403)
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank-error"]').wait_for(timeout=5000)
    assert 'whole cluster' in page.locator('[data-whatif="rank-error"]').inner_text()
    assert page.locator('[data-whatif="rank"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_report_without_tenants_says_so(open_risk, risk_data, monkeypatch):
    report = _node_report()
    report['risk']['tenants']['items'] = []
    for g in report['guests']:
        g['tenants'] = []
    app = open_risk('modern', report=report)
    page = app.page
    page.locator('[data-whatif-node="pve1"]').check()
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert 'No tenant is listed for this cluster.' in page.locator('[data-whatif-risk="tenants"]').inner_text()
    assert page.locator('[data-whatif-guest="100"] [data-whatif-tenants]').inner_text() == '-'
    assert not app.errors, app.errors


def test_runtime_the_ranking_speaks_german(open_risk):
    app = open_risk('modern', language='de')
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    assert page.get_by_text('Rangfolge').first.is_visible()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    text = page.locator('[data-whatif="rank-weighting"]').inner_text()
    assert text.startswith('Gewichtung: ausgefallen 1') and 'ein kritischer Gast zählt das 3-Fache' in text
    assert page.locator('[data-whatif-rank-row="storage:ceph"]').inner_text().startswith('Gemeinsamer Speicher')
    assert not app.errors, app.errors


def test_runtime_a_standby_ranks_too(browser):  # noqa: F811
    extra = dict(SSE_TOKEN)
    extra[('GET', '/api/clusters/c1/reports/summary')] = (200, {'period': 'day', 'data_points': 0, 'timestamps': []})
    extra[('GET', '/api/clusters/c1/reports/top-vms')] = (200, [])
    extra[('GET', URL + '/options')] = (200, _options())
    extra[('POST', RANK)] = (200, _ranking())
    app = _App(browser, _FakeServer(role='standby', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra=extra))
    try:
        page = app.page
        page.get_by_text('Testi').first.click()
        page.wait_for_timeout(500)
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press('p')
        page.locator('button', has_text='What-if').first.click()
        page.locator('[data-whatif-view="ranking"]').click()
        page.locator('[data-whatif="rank-run"]').click()
        page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
        assert re.search(r'ceph', page.locator('[data-whatif="rank"]').inner_text())
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- what the report says about stopped guests, an inactive backup storage and what is ranked ------

def _run_node(page, node='pve1'):
    page.locator(f'[data-whatif-node="{node}"]').check()
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)


def test_runtime_stopped_guests_are_stated_next_to_the_counts(open_risk, risk_data):
    app = open_risk('modern', report=_stopped_report())
    page = app.page
    _run_node(page)
    note = page.locator('[data-whatif="stopped-note"]')
    assert note.inner_text().startswith('Stopped guests (3) are not counted as affected or unaffected, they are not running')
    assert note.locator('[data-whatif-basis="assumed"]').count() == 1
    assert page.locator('[data-whatif-count="unaffected"]').inner_text().split()[0] == '0'
    assert not app.errors, app.errors


def test_runtime_a_report_without_stopped_guests_has_no_such_line(open_risk, risk_data):
    app = open_risk('modern')
    _run_node(app.page)
    assert app.page.locator('[data-whatif="stopped-note"]').count() == 0
    # and keeps the HA heading of its limits
    assert app.page.locator('[data-whatif="limits"] h3').inner_text().strip() == 'HA limits and constraints hit'
    assert not app.errors, app.errors


def test_runtime_an_offline_backup_storage_is_said_to_be_inactive_under_a_fitting_heading(open_risk, risk_data):
    app = open_risk('corporate', report=_pbs_offline_report())
    page = app.page
    page.locator('[data-whatif-scenario="pbs_failure"]').click()
    page.locator('[data-whatif-field="pbs"]').select_option('pbs1')
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="pbs"]').wait_for(timeout=5000)
    limits = page.locator('[data-whatif="limits"]')
    assert limits.locator('h3').inner_text().strip() == 'Backup limits and gaps found'
    assert 'HA limits' not in limits.inner_text()
    inactive = limits.locator('[data-whatif-limit="pbs_inactive"]')
    assert inactive.inner_text().startswith('pbs1 is not active on any node right now (offline or not reachable)')
    assert inactive.locator('[data-whatif-basis="known"]').count() == 1
    assert limits.locator('[data-whatif-limit="pbs_points_unread"]').count() == 1
    # the stopped guest 104 is tied to the storage by the job: the line says how stopped guests count here
    assert page.locator('[data-whatif="stopped-note"]').inner_text().startswith(
        'Stopped guests (1) count as affected only where restore points or a backup job tie them')
    assert not app.errors, app.errors


def test_runtime_the_ranking_says_it_ranks_shared_storages_only(open_risk):
    app = open_risk('modern')
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    note = page.locator('[data-whatif-rank-note="rank_shared_only"]')
    assert note.inner_text().startswith('Only shared storages are ranked: a local storage fails with its node')
    assert page.locator('[data-whatif-rank-note="rank_stopped"]').count() == 0
    # said once, up top, not again in the list of assumptions
    assert page.locator('[data-whatif="rank-assumptions"] [data-whatif-assumption="rank_shared_only"]').count() == 0
    assert page.locator('[data-whatif="rank-assumptions"] [data-whatif-assumption="rank_cheap"]').is_visible()
    assert not app.errors, app.errors


def test_runtime_the_ranking_of_a_cluster_of_stopped_guests_says_why_everything_is_zero(open_risk):
    app = open_risk('modern', ranking=_ranking('stopped'))
    page = app.page
    page.locator('[data-whatif-view="ranking"]').click()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    note = page.locator('[data-whatif-rank-note="rank_stopped"]')
    assert note.inner_text().startswith('Stopped guests (3) are not counted as affected, they are not running')
    assert note.locator('[data-whatif-basis="assumed"]').count() == 1
    weights = {r.get_attribute('data-whatif-rank-row'): r.locator('[data-whatif-rank-weight]').inner_text()
               for r in page.locator('[data-whatif-rank-row]').all()}
    assert weights['node:pve1'] == '0' and weights['storage:ceph'] == '0'
    assert not app.errors, app.errors


def test_runtime_the_new_statements_speak_german(open_risk, risk_data):
    app = open_risk('modern', language='de', report=_stopped_report(), ranking=_ranking('stopped'))
    page = app.page
    _run_node(page)
    assert page.locator('[data-whatif="stopped-note"]').inner_text().startswith(
        'Gestoppte Gäste (3) zählen weder als betroffen noch als nicht betroffen, sie laufen nicht')
    page.locator('[data-whatif-view="ranking"]').click()
    page.locator('[data-whatif="rank-run"]').click()
    page.locator('[data-whatif="rank"]').wait_for(timeout=5000)
    assert page.locator('[data-whatif-rank-note="rank_shared_only"]').inner_text().startswith(
        'Nur gemeinsame Speicher kommen in die Rangfolge')
    assert not app.errors, app.errors
