"""The recovery report, the restore test settings and the schedule routes, through the app.

  GET  /api/clusters/<id>/recovery-report             every guest of a cluster: last test that
                                                      passed, the backup it restored, restore +
                                                      boot + checks against the RTO, the newest
                                                      backup against the backup SLA, the last
                                                      failure; ?format=csv
  GET  /api/clusters/<id>/recovery-report/<vmid>      one guest, with its checks and last tests
  GET  /api/tenants/<tenant>/recovery-report          every cluster of a tenant
  GET  /api/clusters/<id>/recovery-settings           the cluster's defaults and the rules
  PUT  /api/clusters/<id>/recovery-settings           the defaults (admin)
  PUT  /api/clusters/<id>/recovery-settings/rules     a guest or tag rule (admin)
  DELETE .../recovery-settings/rules/<scope>/<key>
  PUT  /api/pbs/verify-schedule                       400 for what is out of range (was a 500)
  GET  /api/pbs/verify-schedule/status                next run, last run, its results

Who sees what: an admin all of it, an operator whose tenant owns the cluster the whole
cluster, a pool- or ACL-confined caller its own guests only, another tenant nothing; only an
admin no tenant lowers sets what the tests do. A standby takes no write.
MK Oct 2026
"""
import csv
import io
import re
import time
import types

import pytest

from pegaprox.core import recovery

from test_ha_api import ha_env, _standby_of_active  # noqa: F401

NOW = time.time()


def _bk(vmid, hours_ago, kind='qemu'):
    t = int(NOW - hours_ago * 3600)
    iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))
    return {'volid': f"pbs:backup/{'vm' if kind == 'qemu' else 'ct'}/{vmid}/{iso}", 'vmid': vmid,
            'ctime': t, 'subtype': kind}


GUESTS = [
    {'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'tags': 'prod'},
    {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'name': '=cmd|evil', 'tags': ''},
    {'vmid': 102, 'type': 'lxc', 'node': 'pve2', 'name': 'db01', 'tags': 'db;prod'},
    {'vmid': 103, 'type': 'qemu', 'node': 'pve2', 'name': 'tmpl', 'template': 1},
    {'vmid': 900, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'tags': 'pegaprox-verify'},
]
CONTENT = [_bk(100, 3), _bk(100, 27), _bk(101, 40), _bk(102, 2, 'lxc')]


def _manager(api, cid='c1', connected=True):
    m = api.make_fake_manager(cid)
    m.is_connected = connected
    m.config = types.SimpleNamespace(name='Testi', backup_sla_max_age_hours=24)
    m.get_vm_resources.return_value = list(GUESTS)

    def get(url, timeout=None, params=None):
        path = url.split('/api2/json', 1)[1]
        r = types.SimpleNamespace(status_code=200)
        if path == '/nodes':
            data = [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]
        elif path == '/storage':
            data = [{'storage': 'pbs', 'type': 'pbs', 'content': 'backup'}]
        elif path.endswith('/storage/pbs/content'):
            data = list(CONTENT)
        else:
            r.status_code, data = 404, None
        r.json = lambda: {'data': data}
        return r
    m._api_get.side_effect = get
    return api.set_manager(cid, m)


@pytest.fixture
def routes(api, seed, monkeypatch):
    monkeypatch.setattr(recovery, '_backups', {})
    _manager(api)
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def _who(routes, kind):
    seed, api = routes.seed, routes.api
    if kind == 'admin':
        return routes.admin
    if kind == 'operator':
        # the tenant owns the cluster, no pool, no ACL: a cluster-wide operator
        seed.tenant('t_own', ['c1'])
        return api.as_user(seed.user('op', role='user', tenant_id='t_own',
                                     permissions=['backup.view', 'cluster.config', 'pbs.config']))
    if kind == 'no_permission':
        seed.tenant('t_own', ['c1'])
        return api.as_user(seed.user('plain', role='user', tenant_id='t_own', denied=['backup.view']))
    if kind == 'acl_confined':
        # reaches the cluster through a VM ACL on 100 only; its tenant does not own it
        seed.tenant('t_confined', [])
        seed.vm_acl('c1', 100, ['portal'], permissions=['vm.view', 'backup.view'])
        return api.as_user(seed.user('portal', role='user', tenant_id='t_confined',
                                     permissions=['backup.view', 'cluster.config', 'pbs.config']))
    if kind == 'capped_admin':
        # an admin a tenant override lowers to user where it lives, and that tenant owns c1
        seed.tenant('globex', ['c1'])
        return api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                     tenant_permissions={'globex': {'role': 'user'}}))
    if kind == 'other_tenant':
        seed.tenant('acme', ['c2'])
        return api.as_user(seed.user('acme_op', role='user', tenant_id='acme',
                                     permissions=['backup.view', 'cluster.config', 'pbs.config']))
    raise AssertionError(kind)


def _mark(vmid, ok_hours=None, fail_hours=None, seconds=240.0, cause='port 443: nothing listens', backup_hours=5):
    if ok_hours is not None:
        recovery.note_result({'cluster_id': 'c1', 'vmid': vmid, 'status': 'passed', 'id': f'ok{vmid}',
                              'backup_ts': int(NOW - backup_hours * 3600), 'measured_seconds': seconds,
                              'checks': [{'check': 'port', 'target': '22', 'ok': True, 'detail': 'listening'}]},
                             at=NOW - ok_hours * 3600)
    if fail_hours is not None:
        recovery.note_result({'cluster_id': 'c1', 'vmid': vmid, 'status': 'failed', 'id': f'f{vmid}',
                              'restore_ok': True, 'boot_ok': True,
                              'checks': [{'check': 'port', 'target': '443', 'ok': False,
                                          'detail': 'nothing listens'}]}, at=NOW - fail_hours * 3600)


# --- the report ------------------------------------------------------------------------------

def test_the_report_of_a_cluster(routes):
    recovery.save_rule('c1', 'cluster', '', {'rto_minutes': 10}, 'root')
    recovery.save_rule('c1', 'tag', 'db', {'rto_minutes': 2}, 'root')
    _mark(100, ok_hours=24 * 3)
    _mark(102, ok_hours=24 * 2, seconds=300.0)
    _mark(101, fail_hours=1)
    r = routes.admin.get('/api/clusters/c1/recovery-report')
    assert r.status_code == 200, r.data
    body = r.get_json()
    rows = {g['vmid']: g for g in body['guests']}
    # no template, no test guest of a run
    assert sorted(rows) == [100, 101, 102]
    assert [g['vmid'] for g in body['guests']] == [101, 102, 100]        # failing, rto missed, ok
    web, bad, db = rows[100], rows[101], rows[102]
    assert web['state'] == 'ok' and web['rto_state'] == 'met' and web['rto_seconds'] == 600
    assert web['measured_seconds'] == 240.0 and web['tested_backup_age_hours'] == pytest.approx(5, abs=0.1)
    assert web['newest_backup_age_hours'] == pytest.approx(3, abs=0.1) and web['rpo_state'] == 'ok'
    assert web['backup_count'] == 2 and 'last_checks' not in web
    assert db['state'] == 'rto_missed' and db['rto_seconds'] == 120
    assert bad['state'] == 'failing' and bad['last_failure_cause'] == 'port 443: nothing listens'
    assert bad['rpo_state'] == 'breached' and bad['last_success_at'] is None
    assert body['summary'] == {'ok': 1, 'stale': 0, 'failing': 1, 'never': 0, 'rto_missed': 1,
                               'total': 3, 'rpo_breached': 1, 'no_backup': 0}
    assert body['backups_state'] == 'ok' and body['sla_hours'] == 24
    assert body['settings']['rto_minutes'] == 10 and body['settings']['isolation'] == 'link_down'


def test_stale_and_never(routes):
    _mark(100, ok_hours=24 * 40)
    body = routes.admin.get('/api/clusters/c1/recovery-report?days=30').get_json()
    states = {g['vmid']: g['state'] for g in body['guests']}
    assert states == {100: 'stale', 101: 'never', 102: 'never'}
    body = routes.admin.get('/api/clusters/c1/recovery-report?days=60').get_json()
    assert {g['vmid']: g['state'] for g in body['guests']}[100] == 'ok'


def test_the_backups_are_read_once_for_the_report_and_its_next_reads(routes):
    mgr = routes.api.make_fake_manager  # noqa: F841
    from pegaprox.globals import cluster_managers
    m = cluster_managers['c1']
    routes.admin.get('/api/clusters/c1/recovery-report')
    routes.admin.get('/api/clusters/c1/recovery-report')
    routes.admin.get('/api/clusters/c1/recovery-report/100')
    paths = [c.args[0].split('/api2/json', 1)[1] for c in m._api_get.call_args_list]
    assert paths == ['/nodes', '/storage', '/nodes/pve1/storage/pbs/content']
    routes.admin.get('/api/clusters/c1/recovery-report?refresh=1')
    assert m._api_get.call_count == 3          # under a minute old: still the same read


def test_csv_export_neutralises_formulas(routes):
    _mark(100, ok_hours=1)
    r = routes.admin.get('/api/clusters/c1/recovery-report?format=csv')
    assert r.status_code == 200 and r.mimetype == 'text/csv'
    assert 'attachment; filename="recovery-c1.csv"' in r.headers['Content-Disposition']
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0] == list(recovery.CSV_COLUMNS)
    by_id = {row[1]: row for row in rows[1:]}
    assert by_id['101'][2] == "'=cmd|evil" and by_id['100'][0] == 'Testi' and by_id['100'][5] == 'ok'


@pytest.mark.parametrize('query', ['days=0', 'days=366', 'days=abc', 'format=xml'])
def test_a_bad_query_is_a_400(routes, query):
    r = routes.admin.get(f'/api/clusters/c1/recovery-report?{query}')
    assert r.status_code == 400, r.data


def test_an_offline_cluster_says_so(routes):
    _manager(routes.api, connected=False)
    assert routes.admin.get('/api/clusters/c1/recovery-report').status_code == 503


@pytest.mark.parametrize('kind,code,vmids', [
    ('admin', 200, [100, 101, 102]),
    ('operator', 200, [100, 101, 102]),
    ('no_permission', 403, None),
    ('acl_confined', 200, [100]),
    ('capped_admin', 200, [100, 101, 102]),
    ('other_tenant', 403, None),
])
def test_who_sees_which_guests(routes, kind, code, vmids):
    c = _who(routes, kind)
    r = c.get('/api/clusters/c1/recovery-report')
    assert r.status_code == code, (kind, r.data)
    if vmids is not None:
        body = r.get_json()
        assert sorted(g['vmid'] for g in body['guests']) == vmids
        if kind == 'acl_confined':
            # nothing of the test network, the storage or other guests
            assert body['settings'] == {'rto_minutes': None} and body['summary']['total'] == 1
    r = c.get('/api/clusters/c1/recovery-report?format=csv')
    assert r.status_code == code
    if vmids is not None:
        assert sorted(int(row[1]) for row in list(csv.reader(io.StringIO(r.get_data(as_text=True))))[1:]) == vmids


def test_one_guest_with_its_checks_and_tests(routes, db):
    recovery.save_rule('c1', 'guest', '100', {'ports': [22, 80], 'command': 'curl -sf localhost'}, 'root')
    _mark(100, ok_hours=2)
    db.execute("INSERT INTO backup_verifications (id, cluster_id, vmid, started_at, status, details) "
               "VALUES ('t1', 'c1', 100, '2026-10-09T04:00:00', 'passed', ?)",
               ('{"measured_seconds": 240.0, "source": "schedule", "checks": [{"check": "port", "target": "22", "ok": true}]}',))
    r = routes.admin.get('/api/clusters/c1/recovery-report/100')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['guest']['vmid'] == 100 and body['guest']['last_checks'][0]['target'] == '22'
    assert body['checks']['ports'] == [22, 80] and body['checks']['command'] == 'curl -sf localhost'
    assert body['checks']['source'] == {'rto_minutes': 'default', 'agent': 'default', 'ports': 'guest', 'command': 'guest'}
    assert body['history'][0]['source'] == 'schedule' and body['history'][0]['measured_seconds'] == 240.0
    assert body['backups'][0]['volid'] == _bk(100, 3)['volid']
    # a confined caller: its own guest, with the command masked, and not the next one
    c = _who(routes, 'acl_confined')
    r = c.get('/api/clusters/c1/recovery-report/100')
    assert r.status_code == 200 and r.get_json()['checks']['command'] == '' and r.get_json()['checks']['command_set']
    assert c.get('/api/clusters/c1/recovery-report/101').status_code == 404
    assert _who(routes, 'other_tenant').get('/api/clusters/c1/recovery-report/100').status_code == 403
    assert routes.admin.get('/api/clusters/c1/recovery-report/103').status_code == 404     # a template


def test_the_report_of_a_tenant(routes, api):
    _manager(api, 'c2')
    _manager(api, 'c3', connected=False)
    routes.seed.tenant('acme', ['c2', 'c3'])
    body = routes.admin.get('/api/tenants/acme/recovery-report').get_json()
    assert [c['cluster_id'] for c in body['clusters']] == ['c2', 'c3']
    assert [c['state'] for c in body['clusters']] == ['ok', 'offline']
    assert {g['cluster_id'] for g in body['guests']} == {'c2'} and body['summary']['total'] == 3
    # an admin asks for the default tenant: every cluster
    body = routes.admin.get('/api/tenants/default/recovery-report').get_json()
    assert {c['cluster_id'] for c in body['clusters']} == {'c1', 'c2', 'c3'}
    # a member of acme reads its own tenant and no other one
    member = api.as_user(routes.seed.user('acme_viewer', role='user', tenant_id='acme', permissions=['backup.view']))
    assert member.get('/api/tenants/acme/recovery-report').status_code == 200
    assert member.get('/api/tenants/default/recovery-report').status_code == 403
    assert routes.admin.get('/api/tenants/nope/recovery-report').status_code == 404
    r = routes.admin.get('/api/tenants/acme/recovery-report?format=csv')
    assert r.status_code == 200 and 'recovery-acme.csv' in r.headers['Content-Disposition']


# --- the settings ----------------------------------------------------------------------------

def test_the_settings_round_trip(routes):
    a = routes.admin
    r = a.put('/api/clusters/c1/recovery-settings', json={
        'rto_minutes': 30, 'isolation': 'bridge', 'test_bridge': 'vmbr99', 'test_storage': 'local-zfs',
        'boot_timeout': 300, 'ports': [22]})
    assert r.status_code == 200, r.data
    assert r.get_json()['cluster']['test_bridge'] == 'vmbr99'
    r = a.put('/api/clusters/c1/recovery-settings/rules', json={'scope': 'tag', 'key': 'DB', 'ports': [5432, 22, 5432],
                                                                  'command': 'pg_isready'})
    assert r.status_code == 200 and r.get_json()['rule']['ports'] == [22, 5432]
    r = a.put('/api/clusters/c1/recovery-settings/rules', json={'scope': 'guest', 'key': 102, 'rto_minutes': 5})
    assert r.status_code == 200
    body = a.get('/api/clusters/c1/recovery-settings').get_json()
    assert body['can_edit'] is True and body['cluster']['isolation'] == 'bridge'
    assert [t['scope_key'] for t in body['tags']] == ['db'] and body['tags'][0]['command'] == 'pg_isready'
    assert [g['scope_key'] for g in body['guests']] == ['102']
    plan = recovery.plan_for('c1', 102, tags={'db', 'prod'})
    assert plan['rto_seconds'] == 300 and plan['ports'] == [22, 5432] and plan['command'] == 'pg_isready'
    assert plan['isolation'] == 'bridge' and plan['test_bridge'] == 'vmbr99' and plan['boot_timeout'] == 300
    assert plan['source'] == {'rto_minutes': 'guest', 'agent': 'default', 'ports': 'tag:db', 'command': 'tag:db'}
    # back to inherit: a rule with nothing left goes
    r = a.put('/api/clusters/c1/recovery-settings/rules', json={'scope': 'guest', 'key': '102', 'rto_minutes': None})
    assert r.status_code == 200 and r.get_json()['rule'] is None
    assert a.delete('/api/clusters/c1/recovery-settings/rules/tag/db').status_code == 200
    assert a.delete('/api/clusters/c1/recovery-settings/rules/tag/db').status_code == 404
    body = a.get('/api/clusters/c1/recovery-settings').get_json()
    assert body['guests'] == [] and body['tags'] == []
    audit = routes.seed.db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'backup.recovery_%'").fetchone()[0]
    assert audit == 5


@pytest.mark.parametrize('body,needle', [
    ({'rto_minutes': 0}, 'rto_minutes'),
    ({'rto_minutes': 'fast'}, 'rto_minutes'),
    ({'rto_minutes': True}, 'rto_minutes'),
    ({'isolation': 'none'}, 'isolation'),
    ({'isolation': 'bridge'}, 'test_bridge'),
    ({'test_bridge': 'vmbr0;reboot'}, 'test_bridge'),
    ({'test_storage': '../etc'}, 'test_storage'),
    ({'boot_timeout': 10}, 'boot_timeout'),
    ({'ports': [0]}, 'port'),
    ({'ports': '22'}, 'ports'),
    ({'ports': list(range(1, 30))}, 'ports'),
    ({'command': 'echo a\nreboot'}, 'command'),
    ({'command': 'x' * 501}, 'command'),
    ({'agent': 'sometimes'}, 'agent'),
    ({'nics': 'up'}, 'not a setting'),
])
def test_bad_defaults_are_a_400(routes, body, needle):
    r = routes.admin.put('/api/clusters/c1/recovery-settings', json=body)
    assert r.status_code == 400 and needle in r.get_json()['error'], (body, r.data)


@pytest.mark.parametrize('body', [
    None, [], {'scope': 'node', 'key': 'pve1'}, {'scope': 'guest', 'key': 'web01'}, {'scope': 'guest', 'key': 5},
    {'scope': 'tag', 'key': 'a b'}, {'scope': 'tag', 'key': 'pegaprox-verify'},
    {'scope': 'guest', 'key': 100, 'isolation': 'bridge'}, {'scope': 'guest', 'key': 100, 'ports': [70000]},
])
def test_a_bad_rule_is_a_400(routes, body):
    r = routes.admin.put('/api/clusters/c1/recovery-settings/rules', json=body)
    assert r.status_code == 400, (body, r.data)


@pytest.mark.parametrize('kind,read,write', [
    ('admin', 200, 200),
    ('operator', 200, 403),
    ('no_permission', 403, 403),
    ('acl_confined', 200, 403),
    ('capped_admin', 200, 403),
    ('other_tenant', 403, 403),
])
def test_who_may_read_and_set_the_settings(routes, kind, read, write):
    recovery.save_rule('c1', 'guest', '100', {'command': 'systemctl is-active nginx'}, 'root')
    recovery.save_rule('c1', 'guest', '101', {'rto_minutes': 5}, 'root')
    recovery.save_rule('c1', 'tag', 'prod', {'ports': [443]}, 'root')
    c = _who(routes, kind)
    r = c.get('/api/clusters/c1/recovery-settings')
    assert r.status_code == read, (kind, r.data)
    if read == 200:
        body = r.get_json()
        assert body['can_edit'] is (kind == 'admin')
        if kind == 'acl_confined':
            assert [g['scope_key'] for g in body['guests']] == ['100'] and body['tags'] == []
            assert set(body['cluster']) == {'rto_minutes'}
        if kind != 'admin':
            assert not [g for g in body['guests'] if g.get('command')]
    for method, path, payload in (('put', '/api/clusters/c1/recovery-settings', {'rto_minutes': 15}),
                                  ('put', '/api/clusters/c1/recovery-settings/rules',
                                   {'scope': 'guest', 'key': 101, 'command': 'reboot'}),
                                  ('delete', '/api/clusters/c1/recovery-settings/rules/tag/prod', None)):
        r = getattr(c, method)(path, json=payload) if payload is not None else getattr(c, method)(path)
        assert r.status_code == write, (kind, method, path, r.data)
    if write != 200:
        rules = recovery.load_rules('c1')
        assert rules['cluster'] is None and rules['guest'][101]['command'] is None and 'prod' in rules['tag']


def test_a_standby_takes_no_setting(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    monkeypatch.setattr(recovery, '_backups', {})
    _manager(api)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    for method, path, payload in (('put', '/api/clusters/c1/recovery-settings', {'rto_minutes': 15}),
                                  ('put', '/api/clusters/c1/recovery-settings/rules',
                                   {'scope': 'guest', 'key': 100, 'rto_minutes': 5}),
                                  ('put', '/api/pbs/verify-schedule', {'enabled': True}),
                                  ('post', '/api/clusters/c1/backup-verify',
                                   {'node': 'pve1', 'vmid': 100, 'backup_volid': _bk(100, 3)['volid']})):
        r = getattr(c, method)(path, json=payload)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.data)
    assert recovery.load_rules('c1')['cluster'] is None
    assert recovery.load_schedule()['enabled'] is False
    # the report is a read: a standby answers it from the shared marks
    assert c.get('/api/clusters/c1/recovery-report').status_code == 200


# --- the schedule ------------------------------------------------------------------------------

@pytest.mark.parametrize('body,needle', [
    ({'weekly_count': 'many'}, 'weekly_count'),
    ({'weekly_count': 0}, 'weekly_count'),
    ({'hour': 24}, 'hour'),
    ({'hour': None}, 'hour'),
    ({'day': 'someday'}, 'day'),
    ({'enabled': 'yes'}, 'enabled'),
    ({'scope': 'everything'}, 'scope'),
    ({'max_age_days': 400}, 'max_age_days'),
])
def test_a_bad_schedule_is_a_400_not_a_500(routes, body, needle):
    r = routes.admin.put('/api/pbs/verify-schedule', json=body)
    assert r.status_code == 400 and needle in r.get_json()['error'], (body, r.data)
    assert recovery.load_schedule() == recovery.SCHEDULE_DEFAULT


def test_a_schedule_is_stored_and_armed(routes):
    r = routes.admin.put('/api/pbs/verify-schedule', json={'enabled': True, 'day': 'sat', 'hour': 2,
                                                           'weekly_count': 3, 'scope': 'all', 'max_age_days': 14})
    assert r.status_code == 200, r.data
    assert recovery.load_schedule() == {'enabled': True, 'day': 'sat', 'hour': 2, 'weekly_count': 3,
                                        'scope': 'all', 'max_age_days': 14}
    assert recovery.load_state()['armed_wall'] > NOW - 5
    # what the dialog leaves out stays as it was
    routes.admin.put('/api/pbs/verify-schedule', json={'hour': 6})
    assert recovery.load_schedule()['day'] == 'sat' and recovery.load_schedule()['hour'] == 6
    assert routes.admin.get('/api/pbs/verify-schedule').get_json()['hour'] == 6


@pytest.mark.parametrize('kind,code', [
    ('admin', 200), ('operator', 403), ('acl_confined', 403), ('other_tenant', 403),
])
def test_only_a_caller_confined_nowhere_sets_the_schedule(routes, kind, code):
    # the operator's tenant owns c1 only: the run restores guests on every cluster
    _manager(routes.api, 'c2')
    r = _who(routes, kind).put('/api/pbs/verify-schedule', json={'enabled': True})
    assert r.status_code == code, (kind, r.data)
    assert recovery.load_schedule()['enabled'] is (code == 200)


def test_the_status_of_the_schedule_shows_the_callers_guests(routes):
    # the tenants and ACLs are seeded before the first request reads (and caches) them
    operator, c, nobody = (_who(routes, k) for k in ('operator', 'acl_confined', 'no_permission'))
    routes.admin.put('/api/pbs/verify-schedule', json={'enabled': True, 'day': 'sun', 'hour': 4})
    state = recovery.load_state()
    state['last_run'] = {'slot': '2026-10-04T04:00:00', 'state': 'done', 'started_at': NOW - 3600,
                         'finished_at': NOW - 600, 'reason': '',
                         'picked': [{'cluster_id': 'c1', 'vmid': 100}, {'cluster_id': 'c1', 'vmid': 101},
                                    {'cluster_id': 'c9', 'vmid': 100}],
                         'results': [{'cluster_id': 'c1', 'vmid': 100, 'status': 'passed'},
                                     {'cluster_id': 'c1', 'vmid': 101, 'status': 'failed'},
                                     {'cluster_id': 'c9', 'vmid': 100, 'status': 'skipped'}]}
    recovery.save_state(state)
    body = routes.admin.get('/api/pbs/verify-schedule/status').get_json()
    assert body['policy']['enabled'] is True and body['running'] is False
    assert re.match(r'\d{4}-\d{2}-\d{2}T04:00:00$', body['next_run'])
    assert body['last_run']['counts'] == {'picked': 3, 'passed': 1, 'failed': 1, 'skipped': 1}
    # an operator whose tenant owns c1: not what ran on c9
    body = operator.get('/api/pbs/verify-schedule/status').get_json()
    assert body['last_run']['counts'] == {'picked': 2, 'passed': 1, 'failed': 1, 'skipped': 0}
    body = c.get('/api/pbs/verify-schedule/status').get_json()
    assert [r['vmid'] for r in body['last_run']['results']] == [100]
    assert body['last_run']['counts'] == {'picked': 1, 'passed': 1, 'failed': 0, 'skipped': 0}
    assert nobody.get('/api/pbs/verify-schedule/status').status_code == 403


def test_a_manual_verification_takes_no_bridge_and_a_bad_body_is_a_400(routes, monkeypatch):
    import pegaprox.core.backup_verify as bv
    seen = []
    monkeypatch.setattr(bv, 'start_verification', lambda mgr, data: seen.append(dict(data)) or 'task1')
    ok = {'node': 'pve1', 'vmid': 100, 'backup_volid': _bk(100, 3)['volid']}
    r = routes.admin.post('/api/clusters/c1/backup-verify', json=dict(ok, network_bridge='vmbr0', plan={'isolation': 'none'}))
    assert r.status_code == 200, r.data
    assert 'network_bridge' not in seen[0] and 'plan' not in seen[0] and seen[0]['source'] == 'manual'
    for bad in ({**ok, 'node': '../x'}, {**ok, 'boot_timeout': 5}, {**ok, 'storage': 'a b'},
                {**ok, 'check_agent': 'no'}, {**ok, 'backup_volid': 7}):
        assert routes.admin.post('/api/clusters/c1/backup-verify', json=bad).status_code == 400, bad
    assert routes.admin.post('/api/clusters/c1/backup-verify', data='x', content_type='application/json').status_code == 400
    assert len(seen) == 1
