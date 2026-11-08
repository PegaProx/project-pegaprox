"""Drift covers the firewall, HA rules, backup jobs and access, with policy checks.

The scan reads four more kinds. What it could not read is reported as "not checked" and
keeps its baselines; it is never "no drift". A policy check is judged on data that was
read, so a kind that did not answer can not pass. Events carry a category: a deviation
from the baseline, a policy violation, or an incident that an admin confirmed.

A fake PVE answers by path from a table, in the style of test_drift_failed_reads.py;
events and baselines land in the throwaway test database.
"""
import json

import pytest

import pegaprox.globals as ppglobals
from pegaprox.api import drift

CL = 'c_more'


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


class _Pve:
    host, api_port = 'pve.test', 8006
    cluster_type = 'proxmox'

    def __init__(self):
        self.is_connected = True
        self.reads = []
        self.nodes = {'n1': {'node': 'n1'}}
        self.guests = [{'vmid': 101, 'node': 'n1', 'type': 'qemu'},
                       {'vmid': 102, 'node': 'n1', 'type': 'qemu'}]
        # path under /api2/json -> data, or an int for a status code
        self.routes = {
            '/cluster/options': {'keyboard': 'en-us'},
            '/storage': [],
            '/nodes/n1/network': [{'iface': 'vmbr0', 'type': 'bridge'}],
            '/nodes/n1/qemu/101/config': {'cores': 1, 'net0': 'virtio=AA:BB,bridge=vmbr0,firewall=1'},
            '/nodes/n1/qemu/102/config': {'cores': 1, 'net0': 'virtio=CC:DD,bridge=vmbr0'},
            '/cluster/firewall/options': {'enable': 1, 'policy_in': 'DROP'},
            '/cluster/firewall/rules': [{'pos': 0, 'type': 'in', 'action': 'ACCEPT', 'dport': '22', 'digest': 'x'}],
            '/cluster/firewall/aliases': [{'name': 'lan', 'cidr': '10.0.0.0/24', 'digest': 'x'}],
            '/cluster/firewall/ipset': [{'name': 'mgmt', 'comment': ''}],
            '/cluster/firewall/ipset/mgmt': [{'cidr': '10.0.0.5', 'digest': 'x'}],
            '/cluster/firewall/groups': [{'group': 'web'}],
            '/cluster/firewall/groups/web': [{'pos': 0, 'type': 'in', 'action': 'ACCEPT', 'dport': '443'}],
            '/nodes/n1/firewall/rules': [{'pos': 0, 'type': 'in', 'action': 'DROP'}],
            '/nodes/n1/qemu/101/firewall/rules': [{'pos': 0, 'type': 'in', 'action': 'ACCEPT'}],
            '/cluster/ha/rules': [{'rule': 'r1', 'type': 'node-affinity', 'resources': 'vm:101,vm:102',
                                   'nodes': 'n1'}],
            '/cluster/ha/resources': [{'sid': 'vm:101', 'state': 'started', 'digest': 'x'}],
            '/cluster/backup': [{'id': 'job1', 'schedule': 'daily', 'storage': 'local', 'enabled': 1,
                                 'next-run': 111}],
            '/access/users?full=1': [
                {'userid': 'root@pam', 'enable': 1, 'expire': 0, 'email': 'r@example.test',
                 'keys': 'x!secret', 'password': 'hunter2'},
                {'userid': 'bob@pve', 'enable': 1, 'expire': 0, 'groups': 'ops,dev',
                 'tokens': [{'tokenid': 'ci', 'expire': 1900000000, 'privsep': 1, 'value': 'SECRET'}]}],
            '/access/groups': [{'groupid': 'ops', 'users': 'bob@pve', 'comment': 'x'}],
            '/access/roles': [{'roleid': 'Auditor', 'privs': 'Sys.Audit,Datastore.Audit', 'special': 0}],
            '/access/acl': [{'path': '/', 'roleid': 'Administrator', 'type': 'user', 'ugid': 'root@pam',
                             'propagate': 1}],
        }

    def get_vm_resources(self, max_age=None):
        return [dict(g) for g in self.guests]

    def get_node_status(self):
        return {'n1': {'status': 'online'}}

    def _api_get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        self.reads.append(path)
        hit = self.routes.get(path, 404)
        if isinstance(hit, int):
            return _Resp(hit, None)
        return _Resp(200, hit)


@pytest.fixture
def pve(db, monkeypatch):
    from pegaprox.background import alerts, guest_index
    sent = []
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels', lambda payload, **kw: sent.append(payload))
    monkeypatch.setattr(alerts, '_notification_handlers', [])
    monkeypatch.setattr(drift, '_FW_GUEST_PAUSE', 0)
    drift._fw_guest_cache.clear()
    drift._last_scan.clear()
    p = _Pve()
    p.sent = sent
    ppglobals.cluster_managers[CL] = p
    yield p
    ppglobals.cluster_managers.pop(CL, None)
    guest_index.clear()
    drift._fw_guest_cache.clear()
    drift._last_scan.clear()


def _baselines():
    return drift._load_baselines(CL)


def _kv_policy(db, **checks):
    from pegaprox.core.recovery import _kv_write
    _kv_write(drift._policy_key(CL), checks)


def _events(db, **where):
    q = 'SELECT kind, scope, severity, status, category, diff FROM drift_events WHERE cluster_id=?'
    args = [CL]
    for k, v in where.items():
        q += f' AND {k}=?'
        args.append(v)
    return [dict(r) for r in db.conn.execute(q + ' ORDER BY id', args).fetchall()]


# -- what is read -------------------------------------------------------------------------

def test_the_new_kinds_get_baselines(pve):
    res = drift._scan_cluster(CL, autobaseline=True)
    got = set(_baselines())
    assert {('firewall', 'cluster/options'), ('firewall', 'cluster/rules'), ('firewall', 'cluster/aliases'),
            ('firewall', 'cluster/ipset/mgmt'), ('firewall', 'cluster/group/web'), ('firewall', 'node/n1'),
            ('firewall', 'guest/qemu/101'), ('ha_rules', 'rules'), ('ha_rules', 'resources'),
            ('backup_jobs', 'job1'), ('access', 'users'), ('access', 'groups'), ('access', 'roles'),
            ('access', 'acl')} <= got
    assert res['not_checked'] == []


def test_guest_rules_are_read_only_for_guests_with_the_firewall_on(pve):
    drift._scan_cluster(CL, autobaseline=True)
    assert '/nodes/n1/qemu/101/firewall/rules' in pve.reads
    assert '/nodes/n1/qemu/102/firewall/rules' not in pve.reads
    assert ('firewall', 'guest/qemu/102') not in _baselines()


def test_a_snapshot_holds_no_secret(pve):
    drift._scan_cluster(CL, autobaseline=True)
    blob = json.dumps({f"{k}/{s}": v['snapshot'] for (k, s), v in _baselines().items() if k == 'access'})
    for secret in ('hunter2', 'x!secret', 'SECRET', 'r@example.test'):
        assert secret not in blob
    users = _baselines()[('access', 'users')]['snapshot']
    # a token only as id and expiry; csv lists in a fixed order
    assert users['bob@pve'] == {'enable': 1, 'expire': 0, 'groups': 'dev,ops', 'token:ci': 1900000000}


def test_bookkeeping_fields_are_not_drift(pve):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['next-run'] = 222
    pve.routes['/cluster/firewall/rules'][0]['digest'] = 'y'
    assert drift._scan_cluster(CL)['events_count'] == 0


@pytest.mark.parametrize('path,change,kind,scope,severity', [
    ('/cluster/firewall/rules', lambda d: d.append({'pos': 1, 'type': 'in', 'action': 'ACCEPT'}),
     'firewall', 'cluster/rules', 'warning'),
    ('/nodes/n1/qemu/101/firewall/rules', lambda d: d[0].update(action='DROP'),
     'firewall', 'guest/qemu/101', 'warning'),
    ('/cluster/ha/resources', lambda d: d[0].update(state='stopped'), 'ha_rules', 'resources', 'warning'),
    ('/cluster/backup', lambda d: d[0].update(enabled=0), 'backup_jobs', 'job1', 'warning'),
    ('/access/acl', lambda d: d.append({'path': '/', 'roleid': 'Administrator', 'type': 'user',
                                       'ugid': 'bob@pve', 'propagate': 1}), 'access', 'acl', 'critical'),
])
def test_a_change_is_drift_of_its_kind(pve, db, path, change, kind, scope, severity):
    drift._scan_cluster(CL, autobaseline=True)
    change(pve.routes[path])
    drift._fw_guest_cache.clear()
    res = drift._scan_cluster(CL)
    assert [(e['kind'], e['scope'], e['severity']) for e in res['events']] == [(kind, scope, severity)]
    assert _events(db)[0]['category'] == 'deviation'


def test_a_removed_backup_job_is_reported(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'] = []
    res = drift._scan_cluster(CL)
    assert res['removed'] == ['job1']


def test_pve8_ha_groups_stand_in_for_rules(pve):
    pve.routes['/cluster/ha/rules'] = 501
    pve.routes['/cluster/ha/groups'] = [{'group': 'g1', 'nodes': 'n2,n1', 'digest': 'x'}]
    res = drift._scan_cluster(CL, autobaseline=True)
    assert ('ha_rules', 'groups') in _baselines() and ('ha_rules', 'rules') not in _baselines()
    assert res['kinds']['ha_rules'] == 'checked'
    assert _baselines()[('ha_rules', 'groups')]['snapshot']['g1']['nodes'] == 'n1,n2'


# -- not checked is not "no drift" ---------------------------------------------------------

def test_a_kind_that_cannot_be_read_is_not_checked_and_keeps_its_baseline(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'] = 500
    pve.routes['/access/acl'] = 403
    res = drift._scan_cluster(CL)
    assert res['kinds']['backup_jobs'] == 'not_checked'
    assert res['kinds']['access'] == 'partial'
    assert set(res['not_checked']) == {'backup_jobs', 'access'}
    assert res['removed'] == [] and res['events_count'] == 0
    assert ('backup_jobs', 'job1') in _baselines() and ('access', 'acl') in _baselines()
    assert 'backup_jobs' in res['unread']


def test_a_kind_that_never_answered_is_reported_on_the_first_scan(pve):
    pve.routes['/cluster/backup'] = 500
    res = drift._scan_cluster(CL, autobaseline=True)
    assert res['kinds']['backup_jobs'] == 'not_checked'
    assert drift._last_scan[CL]['kinds']['backup_jobs'] == 'not_checked'


def test_a_node_firewall_read_that_fails_is_not_a_removal(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/nodes/n1/firewall/rules'] = 500
    res = drift._scan_cluster(CL)
    assert res['removed'] == [] and ('firewall', 'node/n1') in _baselines()
    assert res['kinds']['firewall'] == 'partial'


def test_an_ipset_list_that_fails_is_not_a_removal_of_every_ipset(pve):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/firewall/ipset'] = 500
    res = drift._scan_cluster(CL)
    assert res['removed'] == [] and ('firewall', 'cluster/ipset/mgmt') in _baselines()


# -- guest rules at scale ------------------------------------------------------------------

def test_guest_rules_are_paced_and_cached(pve, monkeypatch):
    monkeypatch.setattr(drift, '_FW_GUEST_BUDGET', 2)
    pve.guests = [{'vmid': v, 'node': 'n1', 'type': 'qemu'} for v in range(200, 205)]
    for v in range(200, 205):
        pve.routes[f'/nodes/n1/qemu/{v}/config'] = {'net0': 'virtio=AA,bridge=vmbr0,firewall=1'}
        pve.routes[f'/nodes/n1/qemu/{v}/firewall/rules'] = []
    res = drift._scan_cluster(CL, autobaseline=True)
    reads = [p for p in pve.reads if p.endswith('/firewall/rules') and '/qemu/' in p]
    assert len(reads) == 2 and res['kinds']['firewall'] == 'partial'
    assert len([k for k in _baselines() if k[1].startswith('guest/')]) == 2

    # the next scans take the ones not read yet, and do not read again what is fresh
    pve.reads.clear()
    drift._scan_cluster(CL, autobaseline=True)
    drift._scan_cluster(CL, autobaseline=True)
    reads = [p for p in pve.reads if p.endswith('/firewall/rules') and '/qemu/' in p]
    assert len(reads) == 3 and len(set(reads)) == 3
    assert len([k for k in _baselines() if k[1].startswith('guest/')]) == 5
    assert drift._scan_cluster(CL)['kinds']['firewall'] == 'checked'


# -- policy -------------------------------------------------------------------------------

def test_no_check_runs_until_an_admin_switches_it_on(pve, db):
    pve.routes['/cluster/firewall/options'] = {'enable': 0}
    pve.routes['/access/acl'].append({'path': '/', 'roleid': 'Administrator', 'type': 'user',
                                      'ugid': 'bob@pve'})
    res = drift._scan_cluster(CL, autobaseline=True)
    assert res['policy_failed'] == [] and _events(db, category='policy_violation') == []


def test_an_enabled_check_raises_one_event_per_set_of_offenders(pve, db):
    _kv_policy(db, access_admin_role={'enabled': True, 'allow': ['root@pam']})
    drift._scan_cluster(CL, autobaseline=True)
    assert _events(db, category='policy_violation') == []
    pve.routes['/access/acl'] += [
        {'path': '/', 'roleid': 'Administrator', 'type': 'user', 'ugid': 'bob@pve', 'propagate': 1},
        {'path': '/vms', 'roleid': 'Administrator', 'type': 'token', 'ugid': 'bob@pve!ci', 'propagate': 1},
        {'path': '/', 'roleid': 'PVEAuditor', 'type': 'user', 'ugid': 'amy@pve', 'propagate': 1}]
    res = drift._scan_cluster(CL)
    ev = _events(db, category='policy_violation')
    assert len(ev) == 1 and ev[0]['scope'] == 'policy:access_admin_role' and ev[0]['kind'] == 'access'
    assert ev[0]['severity'] == 'critical' and ev[0]['status'] == 'open'
    assert {d['path'] for d in json.loads(ev[0]['diff'])} == {'user:bob@pve', 'token:bob@pve!ci'}
    assert res['policy_failed'] == ['access_admin_role']
    assert 'policy violation' in pve.sent[-1]['message']

    drift._scan_cluster(CL)
    assert len(_events(db, category='policy_violation')) == 1, 'same offenders, same event'
    # the acl change itself is drift as well: both categories, separate rows
    assert len(_events(db, category='deviation', scope='acl')) >= 1

    pve.routes['/access/acl'].pop(1)
    drift._scan_cluster(CL)
    rows = _events(db, category='policy_violation')
    assert [r['status'] for r in rows] == ['superseded', 'open'], 'offenders changed: a new event'


def test_a_passing_check_closes_its_event(pve, db):
    _kv_policy(db, firewall_cluster_enabled={'enabled': True})
    pve.routes['/cluster/firewall/options'] = {'enable': 0}
    drift._scan_cluster(CL, autobaseline=True)
    assert [r['status'] for r in _events(db, category='policy_violation')] == ['open']
    pve.routes['/cluster/firewall/options'] = {'enable': 1}
    drift._scan_cluster(CL)
    assert [r['status'] for r in _events(db, category='policy_violation')] == ['resolved']


def test_a_check_without_data_is_not_checked_and_never_passes(pve, db):
    _kv_policy(db, backup_none_disabled={'enabled': True}, access_token_expiry={'enabled': True})
    pve.routes['/cluster/backup'] = 500
    pve.routes['/access/users?full=1'] = 500
    drift._scan_cluster(CL, autobaseline=True)
    status = {c['id']: c['status'] for c in drift._policy_view(CL)[0]}
    assert status['backup_none_disabled'] == 'not_checked'
    assert status['access_token_expiry'] == 'not_checked'
    assert status['firewall_cluster_enabled'] == 'disabled'


def test_a_violation_is_not_closed_by_a_scan_that_could_not_check(pve, db):
    _kv_policy(db, backup_none_disabled={'enabled': True})
    pve.routes['/cluster/backup'][0]['enabled'] = 0
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'] = 500
    drift._scan_cluster(CL)
    assert [r['status'] for r in _events(db, category='policy_violation')] == ['open']


def test_no_backup_jobs_at_all_passes_when_the_list_was_read(pve, db):
    _kv_policy(db, backup_none_disabled={'enabled': True})
    pve.routes['/cluster/backup'] = []
    drift._scan_cluster(CL, autobaseline=True)
    assert {c['id']: c['status'] for c in drift._policy_view(CL)[0]}['backup_none_disabled'] == 'pass'


def test_a_token_without_expiry_violates(pve, db):
    _kv_policy(db, access_token_expiry={'enabled': True})
    pve.routes['/access/users?full=1'][1]['tokens'][0]['expire'] = 0
    drift._scan_cluster(CL, autobaseline=True)
    ev = _events(db, category='policy_violation')
    assert json.loads(ev[0]['diff'])[0]['path'] == 'bob@pve!ci'


# -- routes -------------------------------------------------------------------------------

@pytest.fixture
def estate(api, seed, db, pve):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    return seed


def _add_event(db, eid, kind='access', scope='acl', category='deviation', status='open'):
    db.conn.execute("INSERT INTO drift_events (id, cluster_id, kind, scope, severity, summary, diff, "
                    "detected_at, status, category) VALUES (?, ?, ?, ?, 'warning', 's', '[]', "
                    "'2026-10-02T00:00:00', ?, ?)", (eid, CL, kind, scope, status, category))
    db.conn.commit()


@pytest.fixture
def admin(api, estate):
    return api.as_user(estate.user('root', role='admin'))


@pytest.fixture
def auditor(api, estate):
    return api.as_user(estate.user('aud', role='viewer', tenant_id='t', permissions=['admin.audit']))


@pytest.fixture
def operator(api, estate):
    return api.as_user(estate.user('op', role='viewer', tenant_id='t',
                                   permissions=['admin.audit', 'cluster.config']))


@pytest.fixture
def confined(api, estate):
    u = estate.user('acl_user', role='user', tenant_id='t', permissions=['admin.audit', 'vm.view'])
    estate.vm_acl(CL, 100, ['acl_user'], permissions=['vm.view'])
    return api.as_user(u)


def test_events_filter_by_kind_and_category(admin, db):
    _add_event(db, 1, 'access', 'acl')
    _add_event(db, 2, 'firewall', 'cluster/rules')
    _add_event(db, 3, 'access', 'policy:access_admin_role', 'policy_violation')
    base = f'/api/clusters/{CL}/drift/events'
    ids = lambda q: sorted(e['id'] for e in admin.get(base + q).get_json()['events'])
    assert ids('') == [1, 2, 3]
    assert ids('?kind=access') == [1, 3]
    assert ids('?category=policy_violation') == [3]
    assert ids('?kind=access&category=deviation') == [1]
    assert admin.get(base + '?kind=nope').status_code == 400
    assert admin.get(base + '?category=nope').status_code == 400
    assert all('category' in e for e in admin.get(base).get_json()['events'])


def test_status_counts_categories_and_reports_what_was_read(admin, db):
    _add_event(db, 1)
    _add_event(db, 2, category='policy_violation')
    j = admin.get(f'/api/clusters/{CL}/drift/status').get_json()
    assert j['by_category'] == {'deviation': 1, 'policy_violation': 1, 'incident': 0}
    assert j['kinds'] == {}, 'nothing is claimed read before a scan'
    admin.post(f'/api/clusters/{CL}/drift/scan', json={'seed': True})
    j = admin.get(f'/api/clusters/{CL}/drift/status').get_json()
    assert j['kinds']['access'] == 'checked' and j['last_scan_at']


def test_an_admin_confirms_an_incident_and_takes_it_back(admin, db):
    _add_event(db, 5, 'access', 'policy:access_admin_role', 'policy_violation')
    r = admin.post('/api/drift/events/5/incident', json={})
    assert r.status_code == 200 and r.get_json()['category'] == 'incident'
    row = dict(db.conn.execute('SELECT category, confirmed_by FROM drift_events WHERE id=5').fetchone())
    assert row == {'category': 'incident', 'confirmed_by': 'root'}
    assert admin.post('/api/drift/events/5/incident', json={'incident': False}).get_json()['category'] == 'policy_violation'
    assert admin.post('/api/drift/events/5/incident', json={'incident': False}).status_code == 400
    assert admin.post('/api/drift/events/5/incident', json={'incident': 'yes'}).status_code == 400
    assert admin.post('/api/drift/events/999/incident', json={}).status_code == 404


def test_only_an_admin_confirms_an_incident(auditor, operator, db):
    _add_event(db, 6)
    assert auditor.post('/api/drift/events/6/incident', json={}).status_code == 403
    assert operator.post('/api/drift/events/6/incident', json={}).status_code == 403
    assert db.conn.execute('SELECT category FROM drift_events WHERE id=6').fetchone()[0] == 'deviation'


def test_nothing_makes_an_incident_on_its_own(pve, db):
    _kv_policy(db, firewall_cluster_enabled={'enabled': True}, backup_none_disabled={'enabled': True})
    pve.routes['/cluster/firewall/options'] = {'enable': 0}
    pve.routes['/cluster/backup'][0]['enabled'] = 0
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/access/acl'].append({'path': '/', 'roleid': 'Administrator', 'type': 'user', 'ugid': 'x@pve'})
    drift._scan_cluster(CL)
    assert _events(db, category='incident') == []


def test_acknowledge_works_for_every_category_and_promote_refuses_a_violation(admin, operator, db):
    _add_event(db, 7, 'firewall', 'cluster/rules')
    _add_event(db, 8, 'access', 'policy:access_admin_role', 'policy_violation')
    assert admin.post('/api/drift/events/7/acknowledge', json={}).status_code == 200
    assert operator.post('/api/drift/events/8/acknowledge', json={'promote': True}).status_code == 400
    assert db.conn.execute('SELECT status FROM drift_events WHERE id=8').fetchone()[0] == 'open'
    assert admin.post('/api/drift/events/8/acknowledge', json={}).status_code == 200


def test_promote_rebaselines_a_new_kind(operator, pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    res = drift._scan_cluster(CL)
    eid = res['events'][0]['id']
    assert operator.post(f'/api/drift/events/{eid}/acknowledge', json={'promote': True}).status_code == 200
    assert _baselines()[('backup_jobs', 'job1')]['snapshot']['schedule'] == 'weekly'
    assert drift._scan_cluster(CL)['events_count'] == 0


def test_the_policy_is_read_and_set(admin, operator, auditor, db):
    url = f'/api/clusters/{CL}/drift/policy'
    j = auditor.get(url).get_json()
    assert [c['id'] for c in j['checks']] == list(drift.POLICY_CHECKS)
    assert {c['status'] for c in j['checks']} == {'disabled'}
    r = operator.put(url, json={'checks': {'access_admin_role': {'enabled': True, 'allow': ['root@pam', ' ops@pve ']},
                                           'backup_none_disabled': {'enabled': True}}})
    assert r.status_code == 200, r.get_data(as_text=True)
    got = {c['id']: c for c in auditor.get(url).get_json()['checks']}
    assert got['access_admin_role']['enabled'] and got['access_admin_role']['allow'] == ['ops@pve', 'root@pam']
    assert got['access_admin_role']['status'] == 'not_checked', 'enabled, but no scan has judged it'
    assert got['backup_none_disabled']['enabled'] and not got['firewall_cluster_enabled']['enabled']


@pytest.mark.parametrize('body', [
    None, {}, {'checks': {}}, {'checks': []}, {'checks': {'nope': {'enabled': True}}},
    {'checks': {'access_admin_role': {'enabled': 'yes'}}},
    {'checks': {'access_admin_role': 'on'}},
    {'checks': {'access_admin_role': {'allow': 'root@pam'}}},
    {'checks': {'access_admin_role': {'allow': [1]}}},
    {'checks': {'firewall_cluster_enabled': {'allow': ['x']}}},
])
def test_a_bad_policy_is_a_400_and_stores_nothing(operator, db, body):
    r = operator.put(f'/api/clusters/{CL}/drift/policy', json=body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert all(not c['enabled'] for c in drift._policy_view(CL)[0])


def test_changing_the_policy_needs_cluster_config(auditor, db):
    r = auditor.put(f'/api/clusters/{CL}/drift/policy', json={'checks': {'access_admin_role': {'enabled': True}}})
    assert r.status_code == 403
    assert all(not c['enabled'] for c in drift._policy_view(CL)[0])


def test_a_confined_caller_cannot_touch_the_policy_or_an_incident(confined, db):
    _add_event(db, 9)
    assert confined.get(f'/api/clusters/{CL}/drift/policy').status_code == 403
    assert confined.put(f'/api/clusters/{CL}/drift/policy',
                        json={'checks': {'access_admin_role': {'enabled': True}}}).status_code == 403
    assert confined.post('/api/drift/events/9/incident', json={}).status_code == 403


def test_the_policy_view_is_the_leaders_on_a_standby():
    from pegaprox.core import ha
    assert '/api/clusters/<cluster_id>/drift/policy' in ha.LEADER_ONLY_READS


def test_reset_baseline_keeps_policy_violations_and_incidents(operator, pve, db):
    _add_event(db, 11, category='policy_violation')
    _add_event(db, 12, category='incident')
    _add_event(db, 13)
    assert operator.post(f'/api/clusters/{CL}/drift/baseline').status_code == 200
    got = {r[0]: r[1] for r in db.conn.execute('SELECT id, status FROM drift_events WHERE id IN (11,12,13)')}
    assert got == {11: 'open', 12: 'open', 13: 'superseded'}
