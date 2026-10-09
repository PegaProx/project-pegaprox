"""Two silent failures as event alerts: node clocks that drift and guests in a restart loop.

clock_drift reads /nodes/<n>/time of every online node every CLOCK_EVERY and compares it
with this host's clock. Proxmox answers whole seconds, so a node is only reported when it
is surely past the limit and only cleared when it is surely within it.

restart_loop needs no read of its own: the start and reboot tasks in the task list the
other task rules read are kept per guest, and a guest that started `threshold` times within
`restart_window_minutes` raises one incident, closed once it stayed quiet a whole window.

Driven tick by tick against the fake cluster of test_alert_events.py, the rule fields and
who may set them through the real app.
MK Oct 2026
"""
import types

import pytest

from pegaprox.background import alert_events as E

from test_alert_events import NOW, _closed, _mute, _open, _rule, _rules, _store, _task, _who, cluster, sent  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

WALL = 5000.25          # this host's clock while a node is read


@pytest.fixture(autouse=True)
def _state(monkeypatch):
    for name in ('_clock', '_starts', '_backup', '_zfs'):
        monkeypatch.setattr(E, name, {})
    monkeypatch.setattr(E, '_wall', lambda: WALL)


def _times(cluster, **offsets):
    """Each node answers its clock as whole seconds, `offset` seconds from ours."""
    for node, off in offsets.items():
        cluster.answer(f'/nodes/{node}/time', {'time': int(WALL + off), 'localtime': int(WALL + off) + 7200,
                                               'timezone': 'Europe/Vienna'})


# --- node clocks -----------------------------------------------------------------------

def test_a_node_clock_off_alerts_once_on_every_path_and_resolves(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _times(cluster, pve1=10, pve2=0)

    E.check_event_alerts(NOW)

    assert sent.names() == ['Clock of pve1 is off by 10 s']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'clock_drift'
    assert hook['current_value'] == '+10.2 s' and 'ahead of PegaProx' in hook['message']
    assert len(sent.mail) == 1 and 'Offset: +10.2 s' in sent.mail[0][2]
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key']) == ('node', 'pve1', 'clock:pve1')
    assert row['severity'] == 'warning'

    # read every CLOCK_EVERY, not on every tick, and said once
    E.check_event_alerts(NOW + 60)
    assert cluster.count('/nodes/pve1/time') == 1 and len(sent.push) == 1

    _times(cluster, pve1=0)
    E.check_event_alerts(NOW + E.CLOCK_EVERY + 1)
    assert cluster.count('/nodes/pve1/time') == 2
    assert sent.names()[-1] == 'Resolved: clock of pve1' and sent.hooks[-1][0]['event'] == 'resolved'
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'clear'


def test_a_clock_behind_says_so(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift', threshold=5))
    _times(cluster, pve1=-20, pve2=1)
    E.check_event_alerts(NOW)
    assert sent.names() == ['Clock of pve1 is off by 20 s']
    assert 'behind PegaProx, the limit is 5 s' in sent.push[0]['message']
    assert 'PegaProx host' not in sent.push[0]['message']


def test_whole_seconds_too_close_to_call_change_nothing(cluster, sent, monkeypatch, db):
    """2 s off with a limit of 2: the node read 5002 somewhere in a second that may be 1.75 or
    2.75 s ahead of us. Neither raised nor cleared."""
    _rules(monkeypatch, _rule('clock_drift', threshold=2))
    _times(cluster, pve1=2, pve2=0)
    E.check_event_alerts(NOW)
    assert sent.push == [] and _open(db) == []

    _times(cluster, pve1=3)
    E.check_event_alerts(NOW + E.CLOCK_EVERY + 1)
    assert sent.names() == ['Clock of pve1 is off by 3 s']

    # back to the band: the open incident stays, nothing is said
    _times(cluster, pve1=2)
    E.check_event_alerts(NOW + 2 * E.CLOCK_EVERY + 2)
    assert len(sent.push) == 1 and len(_open(db)) == 1


def test_a_slow_answer_says_nothing_about_the_offset(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _times(cluster, pve1=60, pve2=60)
    ticks = iter(range(0, 1000, 6))
    monkeypatch.setattr(E, '_wall', lambda: WALL + next(ticks))
    E.check_event_alerts(NOW)
    assert sent.push == []
    note = E.source_status()['c1']['clock']
    assert note['ok'] is False and '0 of 2 online node(s) read' in note['note']


def test_every_node_off_alike_points_at_this_host(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _times(cluster, pve1=30, pve2=31)
    E.check_event_alerts(NOW)
    assert sorted(sent.names()) == ['Clock of pve1 is off by 30 s', 'Clock of pve2 is off by 31 s']
    assert all('the clock of the PegaProx host may be the one that is wrong' in d['message'] for d in sent.push)


def test_far_off_is_critical(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _times(cluster, pve1=600, pve2=0)
    E.check_event_alerts(NOW)
    assert sent.push[0]['severity'] == 'critical' and _open(db)[0]['severity'] == 'critical'


def test_a_node_rule_offline_nodes_and_nodes_that_left(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift', rid='r1'), _rule('clock_drift', rid='r2', target_type='node',
                                                              target_id='pve2'))
    _times(cluster, pve1=10, pve2=10)
    E.check_event_alerts(NOW)
    assert sorted((r['alert_id'], r['object_key']) for r in _open(db)) == [
        ('r1', 'clock:pve1'), ('r1', 'clock:pve2'), ('r2', 'clock:pve2')]
    # one read per node for both rules
    assert cluster.count('/nodes/pve1/time') == cluster.count('/nodes/pve2/time') == 1

    # pve2 goes offline: not asked, and what was wrong with it stays open
    cluster.nodes['pve2'] = {'status': 'offline'}
    _times(cluster, pve1=0)
    E.check_event_alerts(NOW + E.CLOCK_EVERY + 1)
    assert cluster.count('/nodes/pve2/time') == 1
    assert sorted(r['object_key'] for r in _open(db)) == ['clock:pve2', 'clock:pve2']

    # pve2 leaves the cluster: closed without a word
    del cluster.nodes['pve2']
    sent.push.clear()
    E.check_event_alerts(NOW + 2 * E.CLOCK_EVERY + 2)
    assert _open(db) == [] and sent.push == []
    assert {r['resolved_by'] for r in _closed(db) if r['object_key'] == 'clock:pve2'} == {'gone'}


def test_a_node_mute_holds_its_clock_back(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _mute(db, object_key='node:pve1', now=None)
    _times(cluster, pve1=10, pve2=10)
    E.check_event_alerts(NOW)
    assert sent.names() == ['Clock of pve2 is off by 10 s']


def test_the_read_is_kept_for_the_exporter(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('clock_drift'))
    _times(cluster, pve1=10, pve2=0)
    E.check_event_alerts(NOW)
    hit = E.clock_reading('c1')
    assert hit['at'] == NOW and hit['online'] == ['pve1', 'pve2']
    assert hit['nodes'] == {'pve1': (10.25, 0.5), 'pve2': (0.25, 0.5)}


def test_without_a_clock_rule_no_clock_is_read(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [])
    E.check_event_alerts(NOW)
    assert not [c for c in cluster.calls if c.endswith('/time')]


# --- restart loops ---------------------------------------------------------------------

def _start(upid, at, tid='101', node='pve1', ttype='qmstart', status='OK'):
    return _task(upid, ttype=ttype, node=node, tid=tid, end=at + 30, status=status)


def test_a_restart_loop_alerts_once_and_closes_when_quiet(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    tasks = [_start('S1', NOW - 600), _start('S2', NOW - 400), _start('S3', NOW - 200)]
    cluster.answer('/cluster/tasks', list(tasks))

    E.check_event_alerts(NOW)

    assert sent.names() == ['web01 (101) is in a restart loop']
    (hook, ids), = sent.hooks
    assert hook['metric'] == 'restart_loop' and hook['current_value'] == '3 starts'
    assert 'started 3 times in the last 15 minutes' in hook['message'] and 'pve1' in hook['message']
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key']) == ('vm', '101', 'vm:101')

    # the loop goes on: the incident keeps up, nothing more is sent
    tasks.append(_start('S4', NOW + 20))
    cluster.answer('/cluster/tasks', list(tasks))
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1
    assert 'started 4 times' in _open(db)[0]['message']

    # quiet for a whole window after the last start
    E.check_event_alerts(NOW + 20 + 15 * 60 - 60)
    assert len(sent.push) == 1 and len(_open(db)) == 1
    E.check_event_alerts(NOW + 20 + 15 * 60 + 60)
    assert sent.names()[-1] == 'Resolved: web01 (101) stopped restarting'
    assert _open(db) == []


def test_starts_below_the_count_keep_an_open_loop_open(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop', threshold=3, restart_window_minutes=10))
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 300), _start('S2', NOW - 200), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1
    # one more start after the first three left the window: one start is not quiet
    cluster.answer('/cluster/tasks', [_start('S5', NOW + 500)])
    E.check_event_alerts(NOW + 600)
    assert len(_open(db)) == 1 and len(sent.push) == 1


@pytest.mark.parametrize('extra,alerted', [
    ([], False),                                                                 # two starts
    ([_start('S3', NOW - 100, status='start failed: QEMU exited with code 1')], False),
    ([_start('S3', NOW - 100, ttype='qmstop')], False),
    ([_start('S3', NOW - 100, ttype='qmreboot')], True),
    ([_start('S3', NOW - 100, status='WARNINGS: 1')], True),
    ([_start('S3', NOW - 100, tid='102', node='pve2', ttype='vzstart')], False),  # another guest
    ([_start('S3', NOW - 20 * 60)], False),                                      # outside the window
])
def test_what_counts_as_a_start(cluster, sent, monkeypatch, db, extra, alerted):
    _rules(monkeypatch, _rule('restart_loop'))
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 300), _start('S2', NOW - 200)] + extra)
    E.check_event_alerts(NOW)
    assert bool(sent.push) == alerted, sent.names()


def test_a_container_loop_and_the_targets(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop', rid='rn', target_type='node', target_id='pve2', threshold=2),
           _rule('restart_loop', rid='rv', target_type='vm', target_id='101', threshold=2))
    cluster.answer('/cluster/tasks', [_start('C1', NOW - 300, tid='102', node='pve2', ttype='vzstart'),
                                      _start('C2', NOW - 100, tid='102', node='pve2', ttype='vzreboot')])
    E.check_event_alerts(NOW)
    assert [(r['alert_id'], r['object_key']) for r in _open(db)] == [('rn', 'vm:102')]
    assert sent.names() == ['db01 (102) is in a restart loop']


def test_the_history_is_there_for_a_rule_added_later(cluster, sent, monkeypatch, db):
    """The starts are kept whenever the task list is read, so a loop that began under a
    failed-task rule is seen by a restart rule switched on afterwards."""
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    assert sent.push == []
    _rules(monkeypatch, _rule(), _rule('restart_loop', rid='r2'))
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['web01 (101) is in a restart loop']


def test_an_unreadable_task_list_closes_nothing(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/tasks', None, code=500)
    E.check_event_alerts(NOW + 3600)
    assert len(_open(db)) == 1 and len(sent.push) == 1


def test_a_guest_that_left_closes_its_loop_quietly(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    cluster.guests = [g for g in cluster.guests if g['vmid'] != 101]
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone' and len(sent.push) == 1


def test_a_guest_mute_holds_the_loop_back(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    _mute(db, object_key='vm:101')
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    assert sent.push == [] and _open(db) == []


def test_a_restart_of_pegaprox_does_not_say_it_again(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    tasks = [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)]
    cluster.answer('/cluster/tasks', tasks)
    E.check_event_alerts(NOW)
    for name in ('_tasks', '_starts', '_status'):
        monkeypatch.setattr(E, name, {})
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1 and len(_open(db)) == 1


def test_the_kept_starts_are_bounded(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restart_loop'))
    many = [_start(f'S{i}', NOW - 3000 + i) for i in range(E.RESTART_KEEP + 50)]
    old = [_start('OLD', NOW - E.RESTART_WINDOW_MAX * 60 - 120, tid='102', node='pve2')]
    cluster.answer('/cluster/tasks', many + old)
    E.check_event_alerts(NOW)
    assert len(E._starts['c1'][101]) == E.RESTART_KEEP and 102 not in E._starts['c1']


# --- the rule fields -------------------------------------------------------------------

@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_both_rules_take_their_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Clocks', 'metric': 'clock_drift'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['target_type'], rule['notify_resolved']) == (
        'event', 2, 'cluster', True)
    assert 'restart_window_minutes' not in rule
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Loops', 'metric': 'restart_loop'})
    rule = r.get_json()['alert']
    assert (rule['threshold'], rule['restart_window_minutes']) == (3, 15)
    r = routes.admin.post('/api/clusters/c1/alerts', json={
        'name': 'L', 'metric': 'restart_loop', 'threshold': 5, 'restart_window_minutes': 60,
        'target_type': 'vm', 'target_id': '101'})
    assert (r.get_json()['alert']['threshold'], r.get_json()['alert']['restart_window_minutes']) == (5, 60)
    assert len(store['c1']) == 3


@pytest.mark.parametrize('body,needle', [
    ({'metric': 'clock_drift', 'threshold': 0}, 'threshold'),
    ({'metric': 'clock_drift', 'threshold': 3601}, 'threshold'),
    ({'metric': 'clock_drift', 'threshold': 'soon'}, 'threshold'),
    ({'metric': 'clock_drift', 'target_type': 'vm', 'target_id': '101'}, 'clock rule'),
    ({'metric': 'restart_loop', 'threshold': 1}, 'threshold'),
    ({'metric': 'restart_loop', 'restart_window_minutes': 0}, 'restart_window_minutes'),
    ({'metric': 'restart_loop', 'restart_window_minutes': 1441}, 'restart_window_minutes'),
    ({'metric': 'restart_loop', 'restart_window_minutes': 'soon'}, 'restart_window_minutes'),
    ({'metric': 'restart_loop', 'restart_window_minutes': [15]}, 'restart_window_minutes'),
    ({'metric': 'restart_loop', 'restart_window_minutes': True}, 'restart_window_minutes'),
    ({'metric': 'restart_loop', 'restart_window_minutes': 7.5}, 'restart_window_minutes'),
])
def test_a_bad_rule_is_refused(routes, monkeypatch, body, needle):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json=dict(body, name='x'))
    assert r.status_code == 400 and needle in r.get_json()['error'], r.data
    assert store['c1'] == []


@pytest.mark.parametrize('method,path', [('post', '/api/clusters/c1/alerts'),
                                         ('put', '/api/clusters/c1/alerts/r1')])
def test_a_body_that_is_no_object_is_a_400(routes, monkeypatch, method, path):
    _store(monkeypatch, [_rule('restart_loop', restart_window_minutes=15)])
    c = routes.admin
    for kw in ({'json': ['restart_loop']}, {'json': 'x'}, {'json': None}):
        r = getattr(c, method)(path, **kw)
        assert r.status_code == 400, (kw, r.status_code, r.data)
    # a form body never gets this far: the app takes JSON only
    assert getattr(c, method)(path, data='metric=restart_loop').status_code == 415


def test_a_new_window_starts_the_rule_over(routes, monkeypatch, db):
    store = _store(monkeypatch, [_rule('restart_loop', restart_window_minutes=15)])
    db.conn.execute("INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, object_key, "
                    "triggered_at) VALUES ('x1', 'r1:c1:vm:101', 'r1', 'c1', 'restart_loop', 'vm:101', '2026-10-07')")
    db.conn.commit()
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'name': 'Loops'}).status_code == 200
    assert len(_open(db)) == 1
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'restart_window_minutes': 30})
    assert r.status_code == 200 and store['c1'][0]['restart_window_minutes'] == 30
    assert _open(db) == []
    # moved to another metric, the window goes with it
    routes.admin.put('/api/clusters/c1/alerts/r1', json={'metric': 'cpu'})
    assert 'restart_window_minutes' not in store['c1'][0]


@pytest.mark.parametrize('kind,code', [
    ('operator', 200),
    ('no_permission', 403),
    ('pool_confined', 403),
    ('capped_admin', 403),
    ('other_tenant', 403),
])
@pytest.mark.parametrize('metric', ['clock_drift', 'restart_loop'])
def test_who_may_set_a_rule(routes, monkeypatch, kind, code, metric):
    store = _store(monkeypatch)
    c = _who(routes, kind)
    r = c.post('/api/clusters/c1/alerts', json={'name': 'n', 'metric': metric})
    assert r.status_code == code, (kind, r.data)
    assert len(store['c1']) == (1 if code == 200 else 0)


def test_a_standby_takes_neither_rule(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    store = _store(monkeypatch)
    api.set_manager('c1', api.make_fake_manager('c1'))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    for metric in ('clock_drift', 'restart_loop'):
        r = c.post('/api/clusters/c1/alerts', json={'name': 'n', 'metric': metric})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert store['c1'] == []


def _incident(db, metric, obj, ttype, tid, rid='r1'):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, message, object_key, triggered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f'i-{obj}', f'{rid}:c1:{obj}', rid, 'c1', metric, ttype, tid, tid, 'x', obj, '2026-10-07T00:00:00'))
    db.conn.commit()


def test_a_confined_caller_sees_its_guests_loops_and_no_clock(routes, monkeypatch, db):
    _incident(db, 'clock_drift', 'clock:pve1', 'node', 'pve1')
    _incident(db, 'restart_loop', 'vm:101', 'vm', '101')
    _incident(db, 'restart_loop', 'vm:300', 'vm', '300')
    _mute(db, object_key='clock:pve1')
    _mute(db, object_key='vm:101')
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    _store(monkeypatch)
    c = _who(routes, 'pool_confined')
    rows = c.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert [i['object_key'] for i in rows] == ['vm:101']
    assert [m['object_key'] for m in c.get('/api/clusters/c1/alert-mutes').get_json()['mutes']] == ['vm:101']
    # counterproof: the admin sees all of them
    rows = routes.admin.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert sorted(i['object_key'] for i in rows) == ['clock:pve1', 'vm:101', 'vm:300']
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 2


def test_an_acknowledged_loop_stays_quiet_and_still_closes(routes, cluster, sent, monkeypatch, db):
    """Ack stops the escalation of an incident like any other; the rule still closes it
    once the guest is quiet."""
    _rules(monkeypatch, _rule('restart_loop'))
    cluster.answer('/cluster/tasks', [_start('S1', NOW - 500), _start('S2', NOW - 300), _start('S3', NOW - 100)])
    E.check_event_alerts(NOW)
    row, = _open(db)
    r = routes.admin.post(f"/api/clusters/c1/active-alerts/{row['id']}/ack")
    assert r.status_code == 200 and _open(db)[0]['acked_by'] == 'root'
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1
    E.check_event_alerts(NOW + 100 + 15 * 60 + 60)
    assert _open(db) == [] and sent.names()[-1] == 'Resolved: web01 (101) stopped restarting'


def test_a_clock_incident_mutes_its_node(routes, monkeypatch, db):
    _store(monkeypatch, [_rule('clock_drift')])
    _incident(db, 'clock_drift', 'clock:pve1', 'node', 'pve1')
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-clock:pve1', 'minutes': 60,
                                                                'whole_object': True})
    assert r.status_code == 200 and r.get_json()['mute']['object_key'] == 'node:pve1'
    assert E._target_key_of('clock:pve1') == 'node:pve1'
