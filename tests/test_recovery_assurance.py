"""Recovery assurance, through the app: coverage, gaps, manual confirmations, signed evidence.

  GET    /api/clusters/<id>/recovery-assurance          coverage of critical and all guests, gaps
  GET    /api/clusters/<id>/recovery-evidence           signed evidence (json, csv)
  GET    /api/tenants/<tenant>/recovery-evidence        the same over a tenant
  POST   /api/recovery-evidence/verify                  signature and audit chain head
  POST   /api/clusters/<id>/recovery-confirmations      manual confirmation (admin)
  DELETE /api/clusters/<id>/recovery-confirmations/<id>

A guest is proven only by a passed restore test in the period with an agent check and an
application check; no data and no confirmation make it proven.
MK Oct 2026
"""
import csv
import io
import json
import re
import time

import pytest

import test_recovery_report as base
from test_recovery_report import routes, _who, _manager, _now_at_the_test  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

from pegaprox.core import assurance, recovery
from pegaprox.core.db import get_db


def _passed(vmid, hours=1, checks=None, seconds=100.0):
    checks = [{'check': 'agent', 'target': '', 'ok': True}, {'check': 'port', 'target': '22', 'ok': True}] \
        if checks is None else checks
    recovery.note_result({'cluster_id': 'c1', 'vmid': vmid, 'status': 'passed', 'id': f'run{vmid}',
                          'backup_ts': int(base.NOW - 5 * 3600), 'measured_seconds': seconds,
                          'checks': checks}, at=base.NOW - hours * 3600)


def _set_critical(routes, tags=('prod',)):
    r = routes.admin.put('/api/clusters/c1/recovery-settings', json={'critical_tags': list(tags)})
    assert r.status_code == 200, r.data


def _assurance(c, q=''):
    r = c.get('/api/clusters/c1/recovery-assurance' + q)
    assert r.status_code == 200, r.data
    return r.get_json()


# --- critical tags -----------------------------------------------------------------------------

def test_critical_tags_default_and_validation(routes):
    assert recovery.cluster_settings(recovery.load_rules('c1'))['critical_tags'] == ['critical']
    _set_critical(routes, ['Prod', 'db', 'prod'])
    assert recovery.cluster_settings(recovery.load_rules('c1'))['critical_tags'] == ['db', 'prod']
    for bad in ('prod', ['a b'], ['pegaprox-verify'], [str(i) for i in range(11)]):
        r = routes.admin.put('/api/clusters/c1/recovery-settings', json={'critical_tags': bad})
        assert r.status_code == 400, bad
    # null goes back to the default
    routes.admin.put('/api/clusters/c1/recovery-settings', json={'critical_tags': None})
    assert recovery.cluster_settings(recovery.load_rules('c1'))['critical_tags'] == ['critical']


# --- coverage ----------------------------------------------------------------------------------

def test_coverage_counts_only_proven_guests(routes):
    _set_critical(routes)                        # 100 and 102 are critical
    _passed(100)                                 # agent + port: proven
    _passed(102, checks=[{'check': 'port', 'target': '22', 'ok': True}])   # no agent check
    body = _assurance(routes.admin)
    g = {r['vmid']: r for r in body['guests']}
    assert g[100]['proof'] == 'proven' and g[100]['critical'] is True and g[100]['missing'] == []
    assert g[102]['proof'] == 'not_proven' and g[102]['missing'] == ['agent_check']
    assert 'no_agent_check' in g[102]['gaps']
    # nothing known of 101: not proven, never covered
    assert g[101]['proof'] == 'not_proven' and g[101]['critical'] is False
    assert 'restore_test' in g[101]['missing']
    assert body['coverage']['critical'] == {'total': 2, 'proven': 1, 'not_proven': 1, 'percent': 50.0}
    assert body['coverage']['all']['proven'] == 1 and body['coverage']['all']['total'] == 3


def test_a_test_with_no_application_check_does_not_prove(routes):
    _passed(100, checks=[{'check': 'agent', 'target': '', 'ok': True},
                         {'check': 'booted', 'target': '', 'ok': True}])
    g = {r['vmid']: r for r in _assurance(routes.admin)['guests']}
    assert g[100]['proof'] == 'not_proven' and 'application_check' in g[100]['missing']
    assert 'no_app_checks' in g[100]['gaps']


def test_a_test_outside_the_period_does_not_prove(routes):
    _passed(100, hours=24 * 40)
    g = {r['vmid']: r for r in _assurance(routes.admin, '?days=30')['guests']}
    assert g[100]['proof'] == 'not_proven' and 'test_stale' in g[100]['gaps']
    g = {r['vmid']: r for r in _assurance(routes.admin, '?days=60')['guests']}
    assert g[100]['proof'] == 'proven'


def test_nothing_known_means_no_percentage_and_no_proof(routes):
    body = _assurance(routes.admin)
    assert body['coverage']['critical'] == {'total': 0, 'proven': 0, 'not_proven': 0, 'percent': None}
    assert body['coverage']['all']['proven'] == 0


# --- gaps --------------------------------------------------------------------------------------

def test_gap_kinds(routes):
    recovery.save_rule('c1', 'tag', 'db', {'rto_minutes': 1}, 'root')
    _passed(102, seconds=300.0)                                  # RTO 60 s missed
    recovery.note_result({'cluster_id': 'c1', 'vmid': 101, 'status': 'failed', 'id': 'f101',
                          'restore_ok': True, 'boot_ok': True,
                          'checks': [{'check': 'port', 'target': '443', 'ok': False, 'detail': 'closed'}]},
                         at=base.NOW - 3600)
    body = _assurance(routes.admin)
    kinds = {(g['vmid'], g['kind']) for g in body['gaps']}
    assert (102, 'rto_missed') in kinds
    assert (101, 'app_failing') in kinds
    assert (101, 'backup_old') in kinds                          # newest backup 40 h, SLA 24 h
    assert (100, 'never_tested') in kinds
    assert body['gap_counts']['never_tested'] == 1 and body['gaps_truncated'] is False
    # worst first: a failing check comes before a never tested guest
    order = [g['kind'] for g in body['gaps']]
    assert order.index('app_failing') < order.index('never_tested')


def test_guest_without_backup_is_a_gap(routes):
    base.CONTENT[:] = [b for b in base.CONTENT if b['vmid'] != 100]
    kinds = {(g['vmid'], g['kind']) for g in _assurance(routes.admin)['gaps']}
    assert (100, 'no_backup') in kinds and (100, 'never_tested') not in kinds


def _plan(plan_id, source, target, vms):
    conn = get_db().conn
    conn.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
                 "VALUES (?,?,?,?,?)", (plan_id, 'g', f'plan {plan_id}', source, target))
    for i, (vmid, job) in enumerate(vms):
        conn.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, replication_job_id) VALUES (?,?,?,?)",
                     (f'{plan_id}-{i}', plan_id, vmid, job))
    conn.commit()


def test_site_recovery_plan_gaps(routes):
    from pegaprox.globals import cluster_managers
    other = routes.api.make_fake_manager('c2')
    other.is_connected = False
    routes.api.set_manager('c2', other)
    _plan('p1', 'c1', 'c2', [(100, 'job-1'), (102, '')])
    _plan('p2', 'c1', 'c9', [(100, 'job-2')])
    _plan('p3', 'cX', 'c2', [(100, '')])                          # another source cluster: not ours
    body = _assurance(routes.admin)
    got = {(g['kind'], g['plan_id'], g['vmid']) for g in body['plan_gaps']}
    assert got == {('plan_target_unreachable', 'p1', None), ('plan_no_replication', 'p1', 102),
                   ('plan_target_unreachable', 'p2', None)}
    assert body['gap_counts']['plan_target_unreachable'] == 2
    # a connected target is no gap
    cluster_managers['c2'].is_connected = True
    got = {(g['kind'], g['plan_id']) for g in _assurance(routes.admin)['plan_gaps']}
    assert got == {('plan_no_replication', 'p1'), ('plan_target_unreachable', 'p2')}


def test_a_plan_to_a_cluster_of_another_tenant_is_not_shown(routes):
    other = routes.api.make_fake_manager('c2')
    other.is_connected = True
    routes.api.set_manager('c2', other)
    routes.seed.tenant('t_own', ['c1'])
    routes.seed.tenant('acme', ['c2'])
    _plan('p1', 'c1', 'c2', [(100, ''), (102, '')])     # to acme's cluster
    _plan('p2', 'c1', 'c9', [(100, '')])                # a target that is gone is nobody's

    def gaps(c):
        return {(g['kind'], g['plan_id']) for g in _assurance(c)['plan_gaps']}

    op = routes.api.as_user(routes.seed.user('op_sr', role='user', tenant_id='t_own',
                                             permissions=['backup.view', 'site_recovery.view']))
    assert gaps(op) == {('plan_target_unreachable', 'p2'), ('plan_no_replication', 'p2')}
    blind = routes.api.as_user(routes.seed.user('op_blind', role='user', tenant_id='t_own',
                                                permissions=['backup.view'], denied=['site_recovery.view']))
    assert gaps(blind) == set()
    assert blind.get('/api/clusters/c1/recovery-evidence').get_json()['plan_gaps'] == []
    # counterproof: the admin sees both plans
    assert ('plan_no_replication', 'p1') in gaps(routes.admin)


# --- manual confirmations ----------------------------------------------------------------------

def _confirm(c, **body):
    return c.post('/api/clusters/c1/recovery-confirmations', json=body)


def test_a_confirmation_is_shown_apart_and_proves_nothing(routes):
    r = _confirm(routes.admin, vmid=101, text='Restored by hand on the lab host', expires_days=30)
    assert r.status_code == 200, r.data
    g = {x['vmid']: x for x in _assurance(routes.admin)['guests']}[101]
    assert g['confirmation']['text'] == 'Restored by hand on the lab host'
    assert g['confirmation']['confirmed_by'] == 'root' and g['confirmation']['expires_at']
    assert g['proof'] == 'not_proven' and 'restore_test' in g['missing']
    assert _assurance(routes.admin)['coverage']['all']['proven'] == 0
    # and in the evidence, under manual, not under automatic
    doc = routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()
    e = {x['vmid']: x for x in doc['guests']}[101]
    assert e['manual']['confirmation']['text'].startswith('Restored by hand')
    assert 'confirmation' not in json.dumps(e['automatic'])


def test_an_expired_or_revoked_confirmation_is_gone(routes):
    now = time.time()
    old = assurance.add_confirmation('c1', {'vmid': 100, 'text': 'old', 'expires_at': now - 5}, 'root', now=now - 99)
    cid = _confirm(routes.admin, vmid=102, text='fresh').get_json()['id']
    g = {x['vmid']: x for x in _assurance(routes.admin)['guests']}
    assert g[100]['confirmation'] is None and g[102]['confirmation']['id'] == cid
    assert routes.admin.delete(f'/api/clusters/c1/recovery-confirmations/{cid}').status_code == 200
    assert {x['vmid']: x for x in _assurance(routes.admin)['guests']}[102]['confirmation'] is None
    # the row stays, marked revoked
    row = get_db().conn.execute('SELECT revoked_at, revoked_by FROM recovery_confirmations WHERE id = ?',
                                (cid,)).fetchone()
    assert row['revoked_at'] and row['revoked_by'] == 'root'
    assert routes.admin.delete(f'/api/clusters/c1/recovery-confirmations/{cid}').status_code == 404
    assert old


def test_past_the_row_cap_each_guest_keeps_its_newest_confirmation(routes, monkeypatch):
    """The read is capped. Oldest first, the cap cut off the newest rows, and a guest
    confirmed twice showed the older confirmation."""
    now = time.time()
    monkeypatch.setattr(assurance, 'CONFIRM_ROWS_MAX', 2)
    assurance.add_confirmation('c1', {'vmid': 100, 'text': 'first', 'expires_at': None}, 'root', now=now - 30)
    assurance.add_confirmation('c1', {'vmid': 101, 'text': 'other', 'expires_at': None}, 'root', now=now - 20)
    assurance.add_confirmation('c1', {'vmid': 100, 'text': 'newest', 'expires_at': None}, 'root', now=now - 10)
    got = assurance.load_confirmations('c1', now=now)
    assert got[100]['text'] == 'newest' and got[101]['text'] == 'other'


@pytest.mark.parametrize('body', [
    {'text': 'x'}, {'vmid': 'abc', 'text': 'x'}, {'vmid': 101}, {'vmid': 101, 'text': '  '},
    {'vmid': 101, 'text': 'x' * 501}, {'vmid': 101, 'text': 'x', 'expires_days': 0},
    {'vmid': 101, 'text': 'x', 'expires_days': 'soon'}, {'vmid': 101, 'text': 'x', 'extra': 1},
])
def test_a_bad_confirmation_is_a_400(routes, body):
    assert _confirm(routes.admin, **body).status_code == 400


def test_confirmation_of_an_unknown_guest_is_a_404(routes):
    assert _confirm(routes.admin, vmid=777, text='x').status_code == 404
    assert _confirm(routes.admin, vmid=103, text='x').status_code == 404       # a template
    assert routes.admin.delete('/api/clusters/c1/recovery-confirmations/nothing').status_code == 404


@pytest.mark.parametrize('kind,code', [
    ('admin', 200), ('operator', 403), ('no_permission', 403), ('acl_confined', 403),
    ('capped_admin', 403), ('other_tenant', 403),
])
def test_who_may_confirm(routes, kind, code):
    c = _who(routes, kind)
    r = _confirm(c, vmid=100, text='checked')
    assert r.status_code == code, (kind, r.data)
    if code == 403:
        n = get_db().conn.execute('SELECT COUNT(*) FROM recovery_confirmations').fetchone()[0]
        assert n == 0
        assert c.delete('/api/clusters/c1/recovery-confirmations/0123456789abcdef').status_code == 403


def test_confirmations_are_audited(routes):
    cid = _confirm(routes.admin, vmid=100, text='audited text').get_json()['id']
    routes.admin.delete(f'/api/clusters/c1/recovery-confirmations/{cid}')
    rows = get_db().conn.execute("SELECT action, details FROM audit_log WHERE action = "
                                 "'backup.recovery_confirmation'").fetchall()
    assert len(rows) == 2 and 'audited text' in rows[0]['details'] and 'Withdrew' in rows[1]['details']


def test_a_standby_takes_no_confirmation(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    monkeypatch.setattr(recovery, '_backups', {})
    _manager(api)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = _confirm(c, vmid=100, text='x')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = c.delete('/api/clusters/c1/recovery-confirmations/0123456789abcdef')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert get_db().conn.execute('SELECT COUNT(*) FROM recovery_confirmations').fetchone()[0] == 0
    assert c.get('/api/clusters/c1/recovery-assurance').status_code == 200


# --- evidence ----------------------------------------------------------------------------------

def _run_row(vmid, run_id):
    get_db().conn.execute("INSERT INTO backup_verifications (id, cluster_id, vmid, started_at, completed_at, "
                          "status) VALUES (?,?,?,?,?,?)",
                          (run_id, 'c1', vmid, '2026-10-10T04:00:00', '2026-10-10T04:05:00', 'passed'))
    get_db().conn.commit()


def test_evidence_is_signed_and_tied_to_the_audit_chain(routes):
    _set_critical(routes)
    _passed(100)
    _run_row(100, 'verify-100')
    r = routes.admin.get('/api/clusters/c1/recovery-evidence')
    assert r.status_code == 200 and r.mimetype == 'application/json'
    doc = json.loads(r.get_data(as_text=True))
    assert doc['format'] == assurance.EVIDENCE_FORMAT and doc['scope'] == {'kind': 'cluster', 'id': 'c1'}
    from pegaprox.constants import PEGAPROX_VERSION
    assert doc['pegaprox_version'] == PEGAPROX_VERSION
    e = {x['vmid']: x for x in doc['guests']}[100]
    assert e['proof'] == 'proven' and e['critical'] is True
    assert e['automatic']['last_success']['run_id'] == 'verify-100'
    assert e['automatic']['last_test']['run_id'] == 'run100'
    assert e['manual'] == {'confirmation': None}
    head = doc['audit_head']
    assert head and head['chain_seq'] >= 1 and len(head['hash']) == 64
    assert doc['signature']['value']
    v = routes.admin.post('/api/recovery-evidence/verify', json=doc)
    assert v.status_code == 200 and v.get_json() == {'signature_valid': True, 'audit_chain': 'present'}


def test_the_evidence_notes_name_the_route_that_verifies_it(routes):
    doc = routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()
    named = re.search(r'POST (/api/\S+)', ' '.join(doc['notes']))
    assert named and named.group(1) == '/api/recovery-evidence/verify'
    # the route the note names answers, with the document it came with
    assert routes.admin.post(named.group(1), json=doc).get_json()['signature_valid'] is True


def test_a_changed_document_fails_verification(routes):
    doc = routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()
    doc['coverage']['all']['proven'] = 3
    assert routes.admin.post('/api/recovery-evidence/verify', json=doc).get_json()['signature_valid'] is False
    doc = routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()
    doc['audit_head']['hash'] = '0' * 64
    res = routes.admin.post('/api/recovery-evidence/verify', json=doc).get_json()
    assert res['signature_valid'] is False and res['audit_chain'] == 'absent'
    doc = routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()
    doc['signature']['value'] = None
    assert routes.admin.post('/api/recovery-evidence/verify', json=doc).get_json()['signature_valid'] is False


def test_a_key_twice_or_a_note_in_the_signature_block_does_not_verify(routes):
    url = '/api/recovery-evidence/verify'
    raw = routes.admin.get('/api/clusters/c1/recovery-evidence').get_data(as_text=True)
    assert routes.admin.post(url, data=raw, content_type='application/json').get_json()['signature_valid'] is True
    # a coverage in front of the signed one: a reader that keeps the first key sees 100 %
    forged = raw.replace('"coverage": {', '"coverage": {"all": {"percent": 100.0}}, "coverage": {', 1)
    assert forged != raw
    res = routes.admin.post(url, data=forged, content_type='application/json').get_json()
    assert res['signature_valid'] is False and 'twice' in res['reason']
    for block in ({'note': 'audited, all fine'}, {'alg': 'none'}):
        doc = json.loads(raw)
        doc['signature'].update(block)
        assert routes.admin.post(url, json=doc).get_json()['signature_valid'] is False, block


def test_a_deeply_nested_body_is_a_400(routes):
    body = '[' * 100000 + ']' * 100000
    r = routes.admin.post('/api/recovery-evidence/verify', data=body, content_type='application/json')
    assert r.status_code == 400


def test_verify_wants_a_document(routes):
    for body in ({}, {'format': 'other'}, [1], 'x'):
        assert routes.admin.post('/api/recovery-evidence/verify', json=body).status_code == 400


def test_evidence_csv_and_the_export_is_audited(routes):
    _passed(100)
    r = routes.admin.get('/api/clusters/c1/recovery-evidence?format=csv')
    assert r.status_code == 200 and r.mimetype == 'text/csv'
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0][0] == '# format' and rows[0][-1]                      # signature in the header line
    assert rows[1] == list(assurance.EVIDENCE_CSV_COLUMNS)
    assert {row[1]: row[4] for row in rows[2:]}['100'] == 'proven'
    n = get_db().conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'backup.recovery_evidence'").fetchone()[0]
    assert n == 1


def test_evidence_names_no_check_command(routes):
    _passed(100, checks=[{'check': 'agent', 'target': '', 'ok': True},
                         {'check': 'command', 'target': 'curl -u admin:secret http://x', 'ok': True}])
    raw = routes.admin.get('/api/clusters/c1/recovery-evidence').get_data(as_text=True)
    assert 'secret' not in raw


@pytest.mark.parametrize('query', ['days=0', 'days=abc', 'format=xml'])
def test_evidence_bad_query_is_a_400(routes, query):
    assert routes.admin.get(f'/api/clusters/c1/recovery-evidence?{query}').status_code == 400
    assert routes.admin.get(f'/api/clusters/c1/recovery-assurance?{query}').status_code in (200, 400)


@pytest.mark.parametrize('kind,code,vmids', [
    ('admin', 200, [100, 101, 102]), ('operator', 200, [100, 101, 102]),
    ('no_permission', 403, None), ('acl_confined', 200, [100]), ('other_tenant', 403, None),
])
def test_who_gets_which_evidence(routes, kind, code, vmids):
    c = _who(routes, kind)
    for url in ('/api/clusters/c1/recovery-evidence', '/api/clusters/c1/recovery-assurance'):
        r = c.get(url)
        assert r.status_code == code, (kind, url)
        if vmids is not None:
            assert sorted(g['vmid'] for g in r.get_json()['guests']) == vmids
    if kind == 'acl_confined':
        # what it signs says it saw part of the cluster
        doc = c.get('/api/clusters/c1/recovery-evidence').get_json()
        assert doc['scope'] == {'kind': 'cluster', 'id': 'c1', 'confined': True}
        assert routes.admin.post('/api/recovery-evidence/verify', json=doc).get_json()['signature_valid'] is True
        # the plans of the cluster are not theirs
        _plan('p9', 'c1', 'c9', [(100, '')])
        assert c.get('/api/clusters/c1/recovery-assurance').get_json()['plan_gaps'] == []
        assert c.get('/api/clusters/c1/recovery-evidence').get_json()['plan_gaps'] == []
        assert routes.admin.get('/api/clusters/c1/recovery-evidence').get_json()['plan_gaps']


def test_tenant_evidence(routes):
    _passed(100)
    r = routes.admin.get('/api/tenants/default/recovery-evidence')
    assert r.status_code == 200, r.data
    doc = r.get_json()
    assert doc['scope'] == {'kind': 'tenant', 'id': 'default'}
    assert routes.admin.post('/api/recovery-evidence/verify', json=doc).get_json()['signature_valid'] is True
    assert routes.admin.get('/api/tenants/nope/recovery-evidence').status_code == 404
    assert routes.admin.get('/api/tenants/default/recovery-evidence?format=xml').status_code == 400
    other = _who(routes, 'other_tenant')
    assert other.get('/api/tenants/default/recovery-evidence').status_code == 403
