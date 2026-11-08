"""Guests without a backup job: the overview across every cluster and the alert source.

Proxmox answers GET /cluster/backup-info/not-backed-up with the guests no vzdump job
of the cluster covers. The alert rule `backup_coverage` reads it once per cluster every
BACKUP_EVERY in the event engine (pegaprox/background/alert_events.py) and raises one
incident per guest; GET /api/backup-coverage lists the same guests for every cluster
the caller reaches, guest by guest as far as the caller may see them. Both share one
read. The cluster is faked at the API paths it is asked.
MK Oct 2026
"""
import time
import types

import pytest

from pegaprox.background import alert_events as E
from pegaprox.background import alerts as A

from test_alert_events import (NOW, _Cluster, _closed, _mute, _open, _rule, _rules,  # noqa: F401
                               cluster, sent)
from test_ha_api import ha_env, _standby_of_active, _active_with_standby  # noqa: F401
from test_ha_loop_gates import _drive, role  # noqa: F401

PATH = '/cluster/backup-info/not-backed-up'

GUESTS = [
    {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'status': 'running'},
    {'vmid': 102, 'type': 'lxc', 'node': 'pve2', 'name': 'db01', 'status': 'stopped'},
    {'vmid': 103, 'type': 'qemu', 'node': 'pve2', 'name': 'lab', 'status': 'running', 'tags': 'No-Backup;lab'},
    {'vmid': 900, 'type': 'qemu', 'node': 'pve1', 'name': 'tpl', 'status': 'stopped', 'template': 1},
]


def _listed(*vmids):
    by_id = {g['vmid']: g for g in GUESTS}
    return [{'vmid': v, 'type': by_id[v]['type'], 'name': by_id[v]['name']} for v in vmids]


@pytest.fixture
def bk(cluster, monkeypatch):
    # raising=False: on a tree without the source the tests below fail at what they check
    monkeypatch.setattr(E, '_backup', {}, raising=False)
    monkeypatch.setattr(E, '_coverage', {}, raising=False)
    cluster.guests = [dict(g) for g in GUESTS]
    return cluster


def _cov(**kw):
    r = _rule('task_failed', **kw)
    for k in ('task_type', 'task_status', 'task_warnings'):
        r.pop(k, None)
    r['metric'] = 'backup_coverage'
    r.setdefault('name', 'backup_coverage rule')
    r['threshold'] = kw.get('threshold', 0)
    r['backup_exclude_tags'] = kw.get('backup_exclude_tags', ['no-backup'])
    return r


# --- the alert -----------------------------------------------------------------------------

def test_a_guest_in_no_backup_job_alerts_once_on_every_path(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))

    E.check_event_alerts(NOW)

    assert sent.names() == ['No backup job covers web01 (101)']
    assert [s for _, s, _, _ in sent.mail] == ['[PegaProx Alert] No backup job covers web01 (101)']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'backup_coverage'
    assert hook['message'] == 'web01 (101) on node pve1 (running) is in no backup job of Testi'
    row, = _open(db, 'r1')
    assert (row['target_type'], row['target_id'], row['object_key']) == ('vm', '101', 'vm:101')
    assert row['operator'] == 'event'

    # polls after it: the same guest, nothing more, and the list is read every BACKUP_EVERY only
    for i in range(1, 7):
        E.check_event_alerts(NOW + 60 * i)
    assert len(sent.push) == len(sent.hooks) == len(sent.mail) == 1
    assert bk.count(PATH) == 2
    assert len(_open(db, 'r1')) == 1


def test_a_job_that_covers_it_says_so(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101, 102))
    E.check_event_alerts(NOW)
    assert sorted(sent.names()) == ['No backup job covers db01 (102)', 'No backup job covers web01 (101)']
    bk.answer(PATH, _listed(102))

    E.check_event_alerts(NOW + E.BACKUP_EVERY)

    assert sent.names()[-1] == 'Resolved: web01 (101) has a backup job'
    assert sent.hooks[-1][0]['event'] == 'resolved' and sent.hooks[-1][0]['severity'] == 'info'
    assert sent.hooks[-1][0]['message'] == 'A backup job of Testi covers web01 (101) now.'
    assert sent.mail[-1][1] == '[PegaProx] Resolved: web01 (101) has a backup job'
    assert [r['object_key'] for r in _open(db)] == ['vm:102']
    assert [(r['object_key'], r['resolved_by']) for r in _closed(db)] == [('vm:101', 'clear')]


def test_a_new_guest_gets_the_grace_of_the_rule(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov(threshold=1))
    bk.answer(PATH, _listed(101, 102))
    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert sent.push == [] and _open(db) == []
    # 102 got its job inside the hour, 101 did not
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW + 2 * E.BACKUP_EVERY)
    E.check_event_alerts(NOW + 3600)
    assert sent.names() == ['No backup job covers web01 (101)']


def test_tagged_guests_and_templates_are_left_out(bk, sent, monkeypatch, db):
    """103 carries the Proxmox tag No-Backup, 102 the PegaProx tag Scratch; the template
    is never asked about."""
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 102, 'Scratch', '')")
    db.conn.commit()
    _rules(monkeypatch, _cov(backup_exclude_tags=['no-backup', 'scratch']))
    bk.answer(PATH, _listed(101, 102, 103, 900))
    E.check_event_alerts(NOW)
    assert sent.names() == ['No backup job covers web01 (101)']
    # counterproof: without the tags every guest but the template counts
    _rules(monkeypatch, _cov(rid='r2', backup_exclude_tags=[]))
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert sorted(r['object_key'] for r in _open(db, 'r2')) == ['vm:101', 'vm:102', 'vm:103']


def test_a_guest_tagged_later_closes_its_alert_quietly(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW)
    bk.guests[0]['tags'] = 'no-backup'
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert len(sent.push) == 1
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone'


def test_the_target_of_the_rule(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov(target_type='node', target_id='pve2', backup_exclude_tags=[]))
    bk.answer(PATH, _listed(101, 102, 103))
    E.check_event_alerts(NOW)
    assert sorted(sent.names()) == ['No backup job covers db01 (102)', 'No backup job covers lab (103)']
    _rules(monkeypatch, _cov(rid='r2', target_type='vm', target_id='101'))
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert [r['object_key'] for r in _open(db, 'r2')] == ['vm:101']


def test_mutes_hold_it_back(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    _mute(db, object_key='vm:101', now=NOW)
    bk.answer(PATH, _listed(101, 102))
    E.check_event_alerts(NOW)
    assert sent.names() == ['No backup job covers db01 (102)']
    # a muted rule says nothing about the guest that is covered now either
    _mute(db, rule_id='r1', now=NOW)
    bk.answer(PATH, [])
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert len(sent.push) == 1 and _open(db) == []


def test_a_guest_that_left_closes_its_alert_quietly(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101, 102))
    E.check_event_alerts(NOW)
    bk.guests = [g for g in bk.guests if g['vmid'] != 102]
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert len(sent.push) == 2
    assert [(r['object_key'], r['resolved_by']) for r in _closed(db)] == [('vm:102', 'gone')]


def test_an_unreadable_list_changes_nothing_and_says_why(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW)
    bk.answer(PATH, None, code=403)
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    note = E.source_status()['c1']['backup']
    assert note['ok'] is False and 'Sys.Audit' in note['note']
    # asked again after a minute, not after five
    E.check_event_alerts(NOW + E.BACKUP_EVERY + 61)
    assert bk.count(PATH) == 3


def test_an_empty_guest_list_is_not_every_guest_gone(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW)
    bk.guests = []
    bk.answer(PATH, [])
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert len(_open(db)) == 1 and len(sent.push) == 1


def test_a_restart_does_not_say_it_again(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov(threshold=2))
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + 7200)
    assert len(sent.push) == 1
    # a new process: what it knew of the guest is gone, the open incident is not
    monkeypatch.setattr(E, '_backup', {})
    monkeypatch.setattr(E, '_coverage', {})
    for t in (NOW + 7300, NOW + 7300 + E.BACKUP_EVERY, NOW + 7300 + 3 * 3600):
        E.check_event_alerts(t)
    assert len(sent.push) == 1 and len(_open(db)) == 1


def test_editing_the_tags_starts_the_rule_over(bk, sent, monkeypatch, db):
    rules = _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    E.check_event_alerts(NOW)
    E.rule_changed('c1', 'r1')
    assert _open(db) == []
    # the next tick reads again at once, and raises what still holds
    E.check_event_alerts(NOW + 60)
    assert bk.count(PATH) == 2 and len(_open(db)) == 1 and len(sent.push) == 2
    assert rules[0]['metric'] == 'backup_coverage'


def test_the_overview_and_the_tick_share_one_read(bk, sent, monkeypatch, db):
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    assert E.not_backed_up('c1', bk, max_age=120, now=NOW - 30)[1] == _listed(101)
    E.check_event_alerts(NOW)
    assert bk.count(PATH) == 1 and sent.names() == ['No backup job covers web01 (101)']
    # older than BACKUP_FRESH: the tick asks for itself
    E.check_event_alerts(NOW + E.BACKUP_EVERY)
    assert bk.count(PATH) == 2


def test_callers_at_the_same_time_share_the_read_under_way(bk, monkeypatch):
    """The overview opened by several people at once, or next to the tick: the second
    caller waits for the read already on its way and takes its answer."""
    import threading
    bk.answer(PATH, _listed(101))
    entered, release = threading.Event(), threading.Event()
    real = bk._api_get

    def slow(url, timeout=10):
        entered.set()
        release.wait(5)
        return real(url, timeout=timeout)
    monkeypatch.setattr(bk, '_api_get', slow)
    got = []
    first = threading.Thread(target=lambda: got.append(E.not_backed_up('c1', bk, max_age=120)))
    first.start()
    assert entered.wait(5)
    second = threading.Thread(target=lambda: got.append(E.not_backed_up('c1', bk, max_age=120)))
    second.start()
    second.join(0.3)
    release.set()
    first.join(5)
    second.join(5)
    assert bk.count(PATH) == 1
    assert [g[1] for g in got] == [_listed(101), _listed(101)]
    # without a max age every caller reads for itself
    E.not_backed_up('c1', bk)
    assert bk.count(PATH) == 2


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_only_the_active_instance_reads_and_sends(which, role, bk, sent, monkeypatch, db):
    role(which)
    _rules(monkeypatch, _cov())
    bk.answer(PATH, _listed(101))
    for name in ('check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
                 'check_update_available_alert', '_periodic_session_cleanup', '_periodic_audit_cleanup'):
        monkeypatch.setattr(A, name, lambda *a, **k: None)
    monkeypatch.setattr(A, '_alert_running', False)
    _drive(monkeypatch, A, A.alert_check_loop)
    if which == 'standby':
        assert bk.count(PATH) == 0 and sent.push == sent.hooks == sent.mail == []
    else:
        assert bk.count(PATH) == 1 and sent.names() == ['No backup job covers web01 (101)']
        assert len(sent.hooks) == len(sent.mail) == 1


# --- the rule fields -----------------------------------------------------------------------

def _store(monkeypatch, rules=None):
    from pegaprox.api import alerts as am
    store = {'c1': [dict(r) for r in (rules or [])]}
    monkeypatch.setattr(am, 'load_cluster_alerts', lambda: store)
    monkeypatch.setattr(am, 'save_cluster_alerts', lambda a: store.update(a))
    return store


@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_a_coverage_rule_takes_its_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Backups', 'metric': 'backup_coverage'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['notify_resolved']) == ('event', 1, True)
    assert rule['backup_exclude_tags'] == ['no-backup']
    assert store['c1'][0]['backup_exclude_tags'] == ['no-backup']
    r = routes.admin.post('/api/clusters/c1/alerts', json={
        'name': 'b', 'metric': 'backup_coverage', 'threshold': 0, 'backup_exclude_tags': 'no-backup, Scratch;lab NO-BACKUP'})
    rule = r.get_json()['alert']
    assert rule['threshold'] == 0 and rule['backup_exclude_tags'] == ['no-backup', 'Scratch', 'lab']
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'c', 'metric': 'backup_coverage',
                                                           'backup_exclude_tags': []})
    assert r.get_json()['alert']['backup_exclude_tags'] == []


@pytest.mark.parametrize('body,needle', [
    ({'threshold': 721}, 'threshold'),
    ({'threshold': -1}, 'threshold'),
    ({'threshold': True}, 'threshold'),
    ({'backup_exclude_tags': 'ok, n?pe'}, 'no tag'),
    ({'backup_exclude_tags': ['ok', 3]}, 'list of words'),
    ({'backup_exclude_tags': {'a': 1}}, 'list of words'),
    ({'backup_exclude_tags': 'x' * 65}, 'no tag'),
    ({'backup_exclude_tags': [f't{i}' for i in range(21)]}, 'at most 20'),
    ({'target_type': 'vm', 'target_id': 'web01'}, 'numeric'),
])
def test_a_bad_coverage_rule_is_refused(routes, monkeypatch, body, needle):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json=dict(body, name='x', metric='backup_coverage'))
    assert r.status_code == 400 and needle in r.get_json()['error'], r.data
    assert store['c1'] == []


def test_new_tags_start_the_rule_over_and_another_metric_drops_them(routes, monkeypatch, db):
    store = _store(monkeypatch, [_cov()])
    db.conn.execute("INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, object_key, "
                    "triggered_at) VALUES ('x1', 'r1:c1:vm:101', 'r1', 'c1', 'backup_coverage', 'vm:101', '2026-10-01')")
    db.conn.commit()
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'name': 'Nightly'}).status_code == 200
    assert len(_open(db)) == 1 and store['c1'][0]['backup_exclude_tags'] == ['no-backup']
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'backup_exclude_tags': 'no-backup,lab'})
    assert r.status_code == 200 and r.get_json()['alert']['backup_exclude_tags'] == ['no-backup', 'lab']
    assert _open(db) == []
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'metric': 'snapshot_age'})
    assert r.status_code == 200 and 'backup_exclude_tags' not in store['c1'][0]


def test_a_standby_takes_no_coverage_rule(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    store = _store(monkeypatch)
    api.set_manager('c1', api.make_fake_manager('c1'))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post('/api/clusters/c1/alerts', json={'name': 'b', 'metric': 'backup_coverage'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert store['c1'] == []


# --- the overview --------------------------------------------------------------------------

class _Mgr(_Cluster):
    def __init__(self, cid, name, guests, uncovered, code=200, connected=True, cluster_type='proxmox'):
        super().__init__(guests=guests, name=name)
        self.cluster_id, self.is_connected, self.cluster_type = cid, connected, cluster_type
        self.answer(PATH, uncovered, code=code)

    def get_pools(self):
        return []


C2_GUESTS = [{'vmid': 201, 'type': 'qemu', 'node': 'b1', 'name': 'erp', 'status': 'running'}]


@pytest.fixture
def overview(api, seed, monkeypatch):
    monkeypatch.setattr(E, '_coverage', {}, raising=False)
    c1 = api.set_manager('c1', _Mgr('c1', 'Testi', [dict(g) for g in GUESTS], _listed(101, 102, 103, 900)))
    c2 = api.set_manager('c2', _Mgr('c2', 'Branch', list(C2_GUESTS),
                                    [{'vmid': 201, 'type': 'qemu', 'name': 'erp'}]))
    api.set_manager('c3', _Mgr('c3', 'Cold', [], [], connected=False))
    api.set_manager('c4', _Mgr('c4', 'Locked', [], None, code=403))
    api.set_manager('x1', _Mgr('x1', 'Xen', [], [], cluster_type='xcpng'))
    return types.SimpleNamespace(api=api, seed=seed, c1=c1, c2=c2)


def _get(client, query=''):
    r = client.get('/api/backup-coverage' + query)
    return r.status_code, r.get_json()


def _ids(body):
    return [(g['cluster_id'], g['vmid']) for g in body['guests']]


def test_the_admin_sees_every_cluster(overview, db):
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 102, 'Scratch', '')")
    db.conn.commit()
    code, body = _get(overview.api.as_user(overview.seed.user('root', role='admin')))
    assert code == 200, body
    assert _ids(body) == [('c2', 201), ('c1', 101), ('c1', 102), ('c1', 103), ('c1', 900)]
    web, db01, lab, tpl = body['guests'][1:]
    assert web == {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 101, 'name': 'web01', 'type': 'qemu',
                   'node': 'pve1', 'status': 'running', 'template': False, 'tags': []}
    assert (db01['type'], db01['status'], db01['tags']) == ('lxc', 'stopped', ['scratch'])
    assert lab['tags'] == ['lab', 'no-backup'] and tpl['template'] is True
    states = {c['cluster_id']: (c['state'], c['count']) for c in body['clusters']}
    assert states == {'c1': ('ok', 4), 'c2': ('ok', 1), 'c3': ('offline', 0), 'c4': ('denied', 0)}
    assert all(c['checked_at'] for c in body['clusters'] if c['state'] == 'ok')
    # one read per cluster, the offline one not asked at all
    assert (overview.c1.count(PATH), overview.c2.count(PATH)) == (1, 1)


def test_a_second_look_reuses_the_read_and_refresh_asks_again(overview, monkeypatch):
    c = overview.api.as_user(overview.seed.user('root', role='admin'))
    _get(c)
    _get(c)
    assert overview.c1.count(PATH) == 1
    real = time.time
    monkeypatch.setattr(E.time, 'time', lambda: real() + 30)
    _get(c, '?refresh=1')
    assert overview.c1.count(PATH) == 2


def test_without_backup_view_nothing_is_read(overview):
    c = overview.api.as_user(overview.seed.user('plain', role='user', denied=['backup.view']))
    code, body = _get(c)
    assert code == 403 and body['required'] == 'backup.view'
    assert overview.c1.count(PATH) == 0
    assert _get(overview.api.anon())[0] == 401


def test_a_viewer_of_the_owning_tenant_sees_its_clusters(overview):
    overview.seed.tenant('acme', ['c1'])
    code, body = _get(overview.api.as_user(overview.seed.user('v', role='viewer', tenant_id='acme')))
    assert code == 200
    assert [c['cluster_id'] for c in body['clusters']] == ['c1']
    assert {g['cluster_id'] for g in body['guests']} == {'c1'}
    assert overview.c2.count(PATH) == 0


def test_a_pool_confined_user_sees_only_the_guests_of_the_pool(overview):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    overview.seed.tenant('t_confined', [])
    overview.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1'), 101: ('qemu', 'other')})
    code, body = _get(overview.api.as_user(overview.seed.user('pooled', role='user', tenant_id='t_confined')))
    assert code == 200, body
    assert _ids(body) == [('c1', 102)]
    assert [(c['cluster_id'], c['count']) for c in body['clusters']] == [('c1', 1)]


def test_a_portal_user_of_the_owning_tenant_sees_their_guest_only(overview):
    overview.seed.tenant('acme', ['c1'])
    overview.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _get(overview.api.as_user(overview.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _ids(body) == [('c1', 103)]


def test_a_confined_admin_sees_their_tenant_only(overview):
    overview.seed.tenant('globex', ['c2'])
    c = overview.api.as_user(overview.seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}}))
    code, body = _get(c)
    assert code == 200
    assert [c['cluster_id'] for c in body['clusters']] == ['c2'] and _ids(body) == [('c2', 201)]
    assert overview.c1.count(PATH) == 0


def test_another_tenant_sees_nothing_of_the_cluster(overview):
    overview.seed.tenant('acme', ['c1'])
    overview.seed.tenant('initech', ['c2'])
    code, body = _get(overview.api.as_user(overview.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200
    assert 'c1' not in {c['cluster_id'] for c in body['clusters']}
    assert 'c1' not in {g['cluster_id'] for g in body['guests']}


def test_a_standby_shows_it_and_writes_nothing(ha_env, seed, monkeypatch, db):  # noqa: F811
    api = ha_env.api
    monkeypatch.setattr(E, '_coverage', {}, raising=False)
    m = api.set_manager('c1', _Mgr('c1', 'Testi', [dict(g) for g in GUESTS], _listed(101)))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    code, body = _get(c)
    assert code == 200 and _ids(body) == [('c1', 101)] and m.count(PATH) == 1
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


def test_the_route_is_served_once(api):
    rules = [r for r in api.app.url_map.iter_rules() if r.rule == '/api/backup-coverage']
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]
