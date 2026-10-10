"""The flight recorder: node state history and GET /api/timeline.

The node state history (core/node_history.py) notes what a read of the nodes found changed
since the read before: offline, online, unknown, maintenance in and out, the cluster's
quorum. GET /api/timeline puts the audit trail, alerts, migrations and balancer moves,
drift, Proxmox tasks and backups, backup verification, node states, site recovery events,
rolling updates, syslog errors and status page incidents into one list, newest first, each
source read under its own access rules, and hangs on every alert, failed task, node going
offline and failed backup what happened on the same guest or node shortly before.

MK Oct 2026
"""
import json
import time
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from pegaprox.core import node_history, timeline as tl
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

CID = 'cluster_1'
ROUTE = f'/api/timeline?cluster={CID}'
NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(autouse=True)
def _fresh():
    node_history.forget()
    yield
    node_history.forget()


def _local(minutes_ago):
    """A time as most sources store it: server-local, no offset."""
    return (NOW - timedelta(minutes=minutes_ago)).astimezone().replace(tzinfo=None).isoformat()


def _utc(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).isoformat(timespec='seconds')


def _epoch(minutes_ago):
    return int((NOW - timedelta(minutes=minutes_ago)).timestamp())


def _ns(**nodes):
    """A get_node_status answer: name -> 'online' | 'offline' | 'maint' | 'maint-offline'."""
    out = {}
    for name, how in nodes.items():
        out[name] = {'status': 'offline' if how.endswith('offline') else 'online',
                     'maintenance_mode': how.startswith('maint')}
    return out


def _rows(db, cid=CID):
    return [(r['node'], r['state'], r['previous'], r['detail'])
            for r in db.query('SELECT * FROM node_state_history WHERE cluster_id = ? ORDER BY id', (cid,))]


# --- the node state history ----------------------------------------------------------------------

def test_a_first_look_at_online_nodes_writes_nothing(db):
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    assert _rows(db) == []


def test_a_node_seen_offline_first_is_written(db):
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    assert _rows(db) == [('pve2', 'offline', '', '')]


def test_a_node_going_away_and_back_is_two_rows(db):
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    assert _rows(db) == [('pve2', 'offline', 'online', ''), ('pve2', 'online', 'offline', '')]
    at = db.query('SELECT at FROM node_state_history LIMIT 1')[0]['at']
    assert at.endswith('+00:00')


def test_maintenance_in_and_out_and_the_reboot_inside_it(db):
    node_history.observe(CID, _ns(pve1='online'))
    node_history.observe(CID, _ns(pve1='maint'))
    node_history.observe(CID, _ns(pve1='maint-offline'))
    node_history.observe(CID, _ns(pve1='maint'))
    node_history.observe(CID, _ns(pve1='online'))
    assert _rows(db) == [('pve1', 'maintenance', 'maintenance_end', ''),
                         ('pve1', 'offline', 'online', 'in maintenance'),
                         ('pve1', 'online', 'offline', ''),
                         ('pve1', 'maintenance_end', 'maintenance', '')]


def test_a_restart_reads_back_where_each_node_stood(db):
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    node_history.forget()      # a restart of PegaProx
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    assert _rows(db) == [('pve2', 'offline', '', '')]
    node_history.forget()
    # it came back while PegaProx was down
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    assert _rows(db)[-1] == ('pve2', 'online', 'offline', '')


def test_quorum_lost_and_back_once_every_node_is_online(db):
    node_history.observe_quorum(CID, None)           # did not answer: says nothing
    node_history.observe_quorum(CID, True)           # quorate on the first look: no event
    assert _rows(db) == []
    node_history.observe(CID, _ns(pve1='online', pve2='online', pve3='online'))
    node_history.observe(CID, _ns(pve1='online', pve2='offline', pve3='offline'))
    node_history.observe_quorum(CID, False, ['pve2', 'pve3'])
    node_history.observe_quorum(CID, False, ['pve2', 'pve3'])
    node_history.observe(CID, _ns(pve1='online', pve2='online', pve3='offline'))
    node_history.observe(CID, _ns(pve1='online', pve2='online', pve3='online'))
    assert [r for r in _rows(db) if r[0] == ''] == [
        ('', 'no_quorum', 'quorate', 'not seen: pve2, pve3'),
        # not while pve3 is still away, then without a read of /cluster/status
        ('', 'quorate', 'no_quorum', 'every node is online')]


def test_each_cluster_keeps_its_newest_rows(db, monkeypatch):
    monkeypatch.setattr(type(db), 'NODE_STATE_KEEP', 4)
    for i in range(5):
        node_history.observe(CID, _ns(pve1='offline' if i % 2 == 0 else 'online'))
    node_history.observe('quiet', _ns(pve9='offline'))
    assert len(_rows(db)) == 4 and len(_rows(db, 'quiet')) == 1


def test_a_standby_records_nothing(db, ha_env):  # noqa: F811
    _standby_of_active(ha_env)
    node_history.observe(CID, _ns(pve1='offline'))
    node_history.observe_quorum(CID, False)
    assert _rows(db) == []


def test_without_a_database_nothing_is_recorded(monkeypatch):
    import pegaprox.core.db as dbmod
    monkeypatch.setattr(dbmod, '_db', None)
    node_history.observe(CID, _ns(pve1='offline'))
    assert dbmod._db is None


def _manager(db, statuses):
    """A real manager whose PVE answers are stubbed: /nodes lists `statuses`."""
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.models.tasks import PegaProxConfig
    db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = PegaProxManager(CID, PegaProxConfig(db.get_cluster(CID)))
    m.is_connected = True
    m.session = MagicMock()
    m._node_status_ttl = 0
    listing = {'data': [{'node': n, 'status': s} for n, s in statuses.items()]}
    m._api_get = lambda url, **kw: types.SimpleNamespace(status_code=200, json=lambda: listing)
    sess = MagicMock()
    sess.get.return_value = types.SimpleNamespace(
        status_code=200, json=lambda: {'data': {'cpu': 0.1, 'memory': {'used': 1, 'total': 2},
                                                'rootfs': {'used': 1, 'total': 2}, 'uptime': 5}})
    m._create_session = lambda: sess
    m._get_live_node_net_rates = lambda: {}
    m._get_native_ha_maintenance_nodes = lambda: set()
    return m


def test_the_poll_of_the_nodes_feeds_the_history(db):
    """Fails without the hook in PegaProxManager.get_node_status."""
    statuses = {'pve1': 'online', 'pve2': 'online'}
    m = _manager(db, statuses)
    assert set(m.get_node_status()) == {'pve1', 'pve2'}
    statuses['pve2'] = 'offline'
    m._api_get = lambda url, **kw: types.SimpleNamespace(
        status_code=200, json=lambda: {'data': [{'node': n, 's': 0, 'status': s} for n, s in statuses.items()]})
    m.get_node_status()
    assert _rows(db) == [('pve2', 'offline', 'online', '')]


def test_the_quorum_read_of_the_ha_monitor_feeds_the_history(db):
    """Fails without the hook in PegaProxManager._ha_cluster_quorum."""
    m = _manager(db, {'pve1': 'online'})
    m._ha_cluster_status = lambda host=None, timeout=10: [
        {'type': 'cluster', 'quorate': 0}, {'type': 'node', 'name': 'pve1', 'online': 1},
        {'type': 'node', 'name': 'pve2', 'online': 0}]
    assert m._ha_cluster_quorum() == (False, ['pve2'])
    assert _rows(db) == [('', 'no_quorum', '', 'not seen: pve2')]


def test_the_table_is_instance_local():
    from pegaprox.core import ha
    assert 'node_state_history' in ha.LOCAL_TABLES and 'node_state_history' not in ha.SYNC_TABLES


# --- the merge, the page and the links (no request) --------------------------------------------

def _ev(kind, ref, minutes_ago, **kw):
    return tl.event(kind, ref, NOW - timedelta(minutes=minutes_ago), cluster=CID, **kw)


def test_times_leave_as_utc_with_their_offset():
    local = tl.stored_time('2026-10-10T12:00:00')
    assert local == datetime(2026, 10, 10, 12, 0).astimezone().astimezone(timezone.utc)
    assert tl.stored_time('2026-10-10T12:00:00', 'utc').isoformat() == '2026-10-10T12:00:00+00:00'
    assert tl.stored_time('2026-10-10 12:00:00+02:00').isoformat() == '2026-10-10T10:00:00+00:00'
    assert tl.stored_time(0).isoformat() == '1970-01-01T00:00:00+00:00'
    assert tl.stored_time('nonsense') is None
    assert _ev('audit', 1, 0)['time'].endswith('+00:00')


@pytest.mark.parametrize('value', ['', 'yesterday', '2026-13-01', '9' * 13, '99999999999', 'x' * 50])
def test_a_time_that_is_none_is_refused(value):
    with pytest.raises(ValueError):
        tl.parse_when(value)


def test_the_links_are_the_same_guest_or_node_within_the_window():
    alert = _ev('alert', 'a1', 0, guest=100, severity='critical', anchor=True)
    moved = _ev('migration', 7, 8, guest=100, node='pve1', nodes=('pve2',))
    drift = _ev('drift', 3, 5, guest=100)
    old = _ev('audit', 9, 30, guest=100)
    other = _ev('task', 'u1', 2, guest=200, node='pve3')
    later = _ev('audit', 10, -1, guest=100)
    events = [alert, moved, drift, old, other, later]
    tl.link([alert], events, timedelta(minutes=10))
    assert [(x['id'], x['seconds_before']) for x in alert['shortly_before']] == \
        [('drift:3', 300), ('migration:7', 480)]
    # a node going offline: what ran on that node shortly before
    down = _ev('node', 1, 0, node='pve3', severity='critical', anchor=True)
    tl.link([down], events + [down], timedelta(minutes=10))
    assert [x['id'] for x in down['shortly_before']] == ['task:u1']
    # no window, no links
    fresh = _ev('alert', 'a2', 0, guest=100, anchor=True)
    tl.link([fresh], events, timedelta(0))
    assert 'shortly_before' not in fresh


def test_the_cluster_losing_quorum_links_the_node_events_before_it():
    quorum = _ev('node', 5, 0, severity='critical', anchor=True)
    node = _ev('node', 4, 3, node='pve2', severity='critical', anchor=True)
    audit = _ev('audit', 1, 2)
    tl.link([quorum], [quorum, node, audit], timedelta(minutes=10))
    assert [x['id'] for x in quorum['shortly_before']] == ['node:4']


def test_a_page_goes_on_from_a_cursor_within_the_same_second():
    """The audit trail stores microseconds, the cursor carries seconds: an event later in the
    same second as the last of a page must still come on the next one."""
    base = NOW.replace(microsecond=0)
    events = [tl.event('audit', i, base + timedelta(microseconds=900000 - i * 100000), cluster=CID)
              for i in range(1, 6)]
    since, until = base - timedelta(minutes=1), base + timedelta(minutes=1)
    first, more = tl.page(events, since, until, limit=2)
    rest, _ = tl.page(events, since, until, before=tl.parse_cursor(tl.cursor_of(first[-1])), limit=10)
    assert more and sorted(e['id'] for e in first + rest) == [f'audit:{i}' for i in range(1, 6)]


def test_a_page_is_newest_first_and_goes_on_from_its_cursor():
    events = [_ev('audit', i, i) for i in range(1, 8)]
    since, until = NOW - timedelta(hours=1), NOW
    first, more = tl.page(events, since, until, limit=3)
    assert [e['id'] for e in first] == ['audit:1', 'audit:2', 'audit:3'] and more
    cursor = tl.parse_cursor(tl.cursor_of(first[-1]))
    rest, more = tl.page(events, since, until, before=cursor, limit=10)
    assert [e['id'] for e in rest] == ['audit:4', 'audit:5', 'audit:6', 'audit:7'] and not more


# --- the route ------------------------------------------------------------------------------------

def _q(db, sql, *params):
    db.conn.execute(sql, params)
    db.conn.commit()


def _audit(db, minutes_ago, action, details, cluster_id=CID, severity='info'):
    db.add_audit_entry('root', action, details, '10.0.0.9', cluster='lab', severity=severity,
                       cluster_id=cluster_id)
    rid = db.query('SELECT MAX(id) AS i FROM audit_log')[0]['i']
    _q(db, 'UPDATE audit_log SET timestamp = ? WHERE id = ?', _local(minutes_ago), rid)


def _alert(db, aid, minutes_ago, target_type, target_id, name, severity='critical', resolved_ago=None,
           cluster_id=CID):
    _q(db, 'INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, '
           'target_name, severity, message, triggered_at, last_fired_at, resolved_at, resolved_by) '
           'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
       aid, f'k{aid}', 'rule1', cluster_id, 'cpu', target_type, str(target_id), name, severity,
       f'{name} CPU above 90%', _local(minutes_ago), _local(minutes_ago),
       _local(resolved_ago) if resolved_ago is not None else None, 'auto' if resolved_ago is not None else None)


TASKS = [
    {'upid': 'UPID:pve2:0001:0002:00000003:qmstart:200:root@pam:', 'node': 'pve2', 'type': 'qmstart',
     'status': 'start failed: no space', 'starttime': _epoch(4), 'endtime': _epoch(3), 'user': 'root@pam',
     'id': '200'},
    {'upid': 'UPID:pve1:0001:0002:00000004:vzdump:100:root@pam:', 'node': 'pve1', 'type': 'vzdump',
     'status': 'OK', 'starttime': _epoch(50), 'endtime': _epoch(45), 'user': 'root@pam', 'id': '100'},
    {'upid': 'UPID:pve1:0001:0002:00000005:aptupdate::root@pam:', 'node': 'pve1', 'type': 'aptupdate',
     'status': 'OK', 'starttime': _epoch(60), 'endtime': _epoch(59), 'user': 'root@pam', 'id': ''},
]
GUESTS = [{'vmid': 100, 'name': 'web01', 'node': 'pve1', 'type': 'qemu'},
          {'vmid': 200, 'name': 'db01', 'node': 'pve2', 'type': 'qemu'}]


@pytest.fixture
def env(api, seed, tmp_path, monkeypatch):
    db = seed.db
    db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = api.make_fake_manager(CID, get_tasks=list(TASKS))
    m.is_connected = True
    m.config = types.SimpleNamespace(name='lab')
    m._vm_resources_cache = (time.time(), list(GUESTS))
    m._node_status_cache = (time.monotonic(), _ns(pve1='online', pve2='online'))
    api.set_manager(CID, m)
    api.set_manager('other', api.make_fake_manager('other', get_tasks=[]))

    _audit(db, 30, 'vm.config', 'Updated config of VM 100 [lab]')
    _audit(db, 12, 'vm.config', 'Updated config of VM 200 [lab]')
    _audit(db, 6, 'node.maintenance', 'Node pve2 entered maintenance [lab]', severity='warning')
    _audit(db, 7, 'vm.config', 'Updated config of VM 300 [other]', cluster_id='other')
    _alert(db, 'al1', 0, 'vm', 100, 'web01')
    _alert(db, 'al2', 2, 'vm', 200, 'db01', severity='warning', resolved_ago=1)
    _alert(db, 'al3', 1, 'node', 'pve2', 'pve2')
    _alert(db, 'al4', 1, 'vm', 300, 'x', cluster_id='other')
    db.add_migration_event(CID, 100, 'web01', 'pve2', 'pve1', 'success', reason='manual by root',
                           timestamp=_local(8))
    db.add_migration_event(CID, 200, 'db01', 'pve1', 'pve2', 'success', reason='pve1 score 80', trigger='balance',
                           timestamp=_local(9))
    _q(db, "INSERT INTO drift_events (cluster_id, kind, scope, severity, summary, diff, detected_at, status) "
           "VALUES (?, 'vm_config', 'qemu/100', 'warning', 'memory changed', '[]', ?, 'open')", CID, _local(5))
    _q(db, "INSERT INTO backup_verifications (id, cluster_id, vmid, vm_name, node, status, phase, error, "
           "started_at) VALUES ('bv1', ?, 200, 'db01', 'pve2', 'failed', 'boot', 'did not boot', ?)", CID, _local(15))
    db.add_node_states(CID, [('pve2', 'offline', 'online', _utc(3), '')])
    _q(db, "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
           "VALUES ('p1', 'g1', 'dr', ?, 'other')",
       CID)
    _q(db, "INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, triggered_by) "
           "VALUES ('e1', 'p1', 'test_failover', 'completed', ?, 'root')",
       (NOW - timedelta(minutes=40)).replace(tzinfo=None).isoformat())
    state = {'nodes': ['pve1', 'pve2'], 'failed_nodes': [{'node': 'pve2', 'error': 'apt failed'}],
             'started_by': 'root'}
    _q(db, "INSERT INTO rolling_update_runs (id, cluster_id, status, state, logs, started_by, started_at, "
           "completed_at) VALUES ('r1', ?, 'failed', ?, '[]', 'root', ?, ?)",
       CID, json.dumps(state), _local(90).replace('T', ' ')[:19], _local(70).replace('T', ' ')[:19])
    _q(db, "INSERT INTO status_incidents (id, title, status, severity, message, components, started_at) "
           "VALUES ('i1', 'Storage slow', 'investigating', 'major', '', '[]', ?)", _local(20))
    _q(db, "INSERT INTO status_incidents (id, title, status, severity, message, components, started_at) "
           "VALUES ('i2', 'Elsewhere', 'investigating', 'minor', '', '[\"other\"]', ?)", _local(20))

    from pegaprox.background import syslog_server
    monkeypatch.setattr(syslog_server, 'DB_FILE', str(tmp_path / 'syslog.db'))
    syslog_server._init_db()
    conn = syslog_server._open_db()
    conn.executemany('INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, severity_text, '
                     'message, protocol) VALUES (?, ?, ?, 0, ?, ?, ?, ?)',
                     [(_local(4), '10.0.0.2', 'pve2', 2, 'crit', 'kernel: I/O error on sda', 'UDP'),
                      (_local(4), '10.0.0.2', 'pve2', 6, 'info', 'cron ran', 'UDP'),
                      (_local(4), '10.0.0.7', 'stranger', 2, 'crit', 'not ours', 'UDP')])
    conn.commit()
    conn.close()
    return types.SimpleNamespace(api=api, seed=seed, db=db, mgr=m)


def _get(client, query=''):
    r = client.get(ROUTE + query)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _admin_client(env):
    return env.api.as_user(env.seed.user('root', role='admin'))


def test_an_admin_sees_every_source_in_one_list(env):
    body = _get(_admin_client(env))
    kinds = {e['kind'] for e in body['events']}
    assert kinds == {'audit', 'alert', 'migration', 'balancer', 'drift', 'task', 'backup', 'backup_verify',
                     'node', 'site_recovery', 'rolling_update', 'syslog', 'incident'}
    times = [e['time'] for e in body['events']]
    assert times == sorted(times, reverse=True) and all(t.endswith('+00:00') for t in times)
    # nothing of the other cluster
    text = json.dumps(body)
    assert 'VM 300' not in text and 'al4' not in text and 'Elsewhere' not in text and 'not ours' not in text
    assert 'cron ran' not in text
    assert all(n['shown'] for n in body['sources'].values())
    ev = {e['id']: e for e in body['events']}
    assert ev['alert:al2:resolved']['what'] == 'alert.resolved'
    assert ev['backup:UPID:pve1:0001:0002:00000004:vzdump:100:root@pam:']['guest_name'] == 'web01'
    assert ev['task:UPID:pve2:0001:0002:00000003:qmstart:200:root@pam:']['severity'] == 'warning'
    assert ev['audit:3']['node'] == 'pve2'
    assert ev['syslog:1']['node'] == 'pve2' and ev['syslog:1']['severity'] == 'critical'
    assert ev['rolling_update:r1:ended']['severity'] == 'warning'
    assert ev['rolling_update:r1:ended']['params']['failed'] == ['pve2']
    assert ev['incident:i1']['severity'] == 'critical'
    assert body['correlation']['window_minutes'] == 10 and 'not cause' in body['correlation']['note']


def test_what_happened_shortly_before_an_alert_is_linked(env):
    body = _get(_admin_client(env))
    alert = next(e for e in body['events'] if e['id'] == 'alert:al1')
    assert alert['anchor'] is True
    linked = [(x['id'], x['seconds_before']) for x in alert['shortly_before']]
    assert ('drift:1', 300) in linked
    assert any(i.startswith('migration:') and s == 480 for i, s in linked)
    # half an hour before is not shortly before
    assert not any(i == 'audit:1' for i, _ in linked)
    # the node going offline: what happened on pve2 shortly before it
    down = next(e for e in body['events'] if e['kind'] == 'node')
    assert down['anchor'] and down['severity'] == 'critical'
    near = [x['id'] for x in down['shortly_before']]
    assert 'task:UPID:pve2:0001:0002:00000003:qmstart:200:root@pam:' in near
    assert 'audit:3' in near and 'syslog:1' in near
    # a resolved alert anchors nothing
    resolved = next(e for e in body['events'] if e['id'] == 'alert:al2:resolved')
    assert not resolved['anchor'] and resolved['shortly_before'] == []


def test_the_window_of_the_links_is_asked_for(env):
    c = _admin_client(env)
    alert = next(e for e in _get(c, '&correlate=6')['events'] if e['id'] == 'alert:al1')
    assert [x['id'] for x in alert['shortly_before']] == ['drift:1']
    alert = next(e for e in _get(c, '&correlate=0')['events'] if e['id'] == 'alert:al1')
    assert alert['shortly_before'] == []


def test_a_kind_filter_keeps_the_links_to_the_others(env):
    body = _get(_admin_client(env), '&kinds=alert')
    assert {e['kind'] for e in body['events']} == {'alert'}
    alert = next(e for e in body['events'] if e['id'] == 'alert:al1')
    assert any(x['kind'] == 'drift' for x in alert['shortly_before'])


def test_severity_filter_and_window(env):
    c = _admin_client(env)
    body = _get(c, '&severity=critical')
    assert body['events'] and {e['severity'] for e in body['events']} == {'critical'}
    frm = (NOW - timedelta(minutes=10)).isoformat()
    body = _get(c, f'&from={frm.replace("+", "%2B")}')
    assert body['events'] and all(e['time'] >= tl.iso(NOW - timedelta(minutes=10)) for e in body['events'])
    assert not any(e['kind'] == 'rolling_update' for e in body['events'])


def test_a_guest_page_has_the_guest_and_its_host(env):
    body = _get(_admin_client(env), '&vmid=200')
    ids = {e['id'] for e in body['events']}
    assert {e['guest'] for e in body['events'] if e['kind'] != 'node'} == {200}
    assert 'backup_verify:bv1' in ids and 'alert:al2' in ids
    # its host pve2 went offline
    assert any(e['kind'] == 'node' and e['node'] == 'pve2' for e in body['events'])
    assert not any(e['kind'] in ('syslog', 'incident', 'rolling_update') for e in body['events'])


def test_a_node_page_has_what_happened_on_the_node(env):
    body = _get(_admin_client(env), '&node=pve2')
    assert body['events']
    for e in body['events']:
        assert e['node'] == 'pve2' or e['kind'] in ('migration', 'balancer', 'alert'), e
    assert any(e['kind'] == 'syslog' for e in body['events'])
    assert any(e['kind'] == 'rolling_update' for e in body['events'])
    assert not any(e['kind'] in ('incident', 'site_recovery') for e in body['events'])


def test_pages_follow_one_another(env):
    c = _admin_client(env)
    seen, before, pages = [], '', 0
    while True:
        body = _get(c, f'&limit=4{before}')
        seen += [e['id'] for e in body['events']]
        pages += 1
        if not body['next_before']:
            break
        before = '&before=' + body['next_before'].replace('+', '%2B')
        assert pages < 20
    whole = [e['id'] for e in _get(c, '&limit=500')['events']]
    assert seen == whole and len(set(seen)) == len(seen) and pages > 2


def test_an_oversized_limit_is_capped(env):
    for i in range(520):
        env.db.add_migration_event(CID, 1000 + i, '', 'pve1', 'pve2', 'success', timestamp=_local(1))
    body = _get(_admin_client(env), '&limit=100000&kinds=migration')
    assert len(body['events']) == 500 and body['next_before']


@pytest.mark.parametrize('query', ['', '&cluster=', '&node=bad%20name', '&vmid=abc', '&vmid=0', '&vmid=1234567890',
                                   '&from=yesterday', '&to=2026-13-40', '&kinds=audit,bogus', '&kinds=,',
                                   '&severity=loud', '&before=nope', '&before=2026-10-10T10:00:00Z|x',
                                   '&correlate=-1', '&correlate=121', '&correlate=ten'])
def test_a_malformed_query_is_a_400(env, query):
    c = _admin_client(env)
    path = '/api/timeline?' + query.lstrip('&') if query.startswith('&cluster=') or query == '' else ROUTE + query
    r = c.get(path)
    assert r.status_code == 400, (query, r.get_data(as_text=True))


def test_a_window_back_to_front_or_too_wide_is_a_400(env):
    c = _admin_client(env)
    frm, to = (NOW - timedelta(days=31)).isoformat(), NOW.isoformat()
    assert c.get(f"{ROUTE}&from={frm.replace('+', '%2B')}&to={to.replace('+', '%2B')}").status_code == 400
    assert c.get(f"{ROUTE}&from={_epoch(1)}&to={_epoch(5)}").status_code == 400
    assert c.get(f"{ROUTE}&from={_epoch(60 * 24 * 29)}&to={_epoch(0)}").status_code == 200


def test_an_unknown_cluster_is_a_404(env):
    assert _admin_client(env).get('/api/timeline?cluster=nope').status_code == 404


def test_the_timeline_wants_a_session(env):
    assert env.api.anon().get(ROUTE).status_code == 401


def test_a_user_without_cluster_view_does_not_get_it(env):
    c = env.api.as_user(env.seed.user('nora', role='viewer', denied=['cluster.view']))
    assert c.get(ROUTE).status_code == 403


def test_a_viewer_gets_what_viewers_read(env):
    c = env.api.as_user(env.seed.user('vicky', role='viewer'))
    body = _get(c)
    src = body['sources']
    # drift and syslog are admin.audit, incidents are for admins, backup verification is vm.backup
    assert src['drift'] == dict(src['drift'], shown=False, why='permission')
    assert src['syslog']['shown'] is False and src['incident']['shown'] is False
    kinds = {e['kind'] for e in body['events']}
    assert {'drift', 'syslog', 'incident'}.isdisjoint(kinds)
    assert {'audit', 'alert', 'migration', 'task'} <= kinds


def test_another_tenant_is_refused(env):
    env.seed.tenant('acme', clusters=['other'])
    c = env.api.as_user(env.seed.user('milton', role='user', tenant_id='acme'))
    assert c.get(ROUTE).status_code == 403


def test_a_confined_admin_is_refused(env):
    env.seed.tenant('globex', clusters=['other'])
    c = env.api.as_user(env.seed.user('gx', role='admin', tenant_id='globex',
                                      tenant_permissions={'globex': {'role': 'user'}}))
    assert c.get(ROUTE).status_code == 403


@pytest.fixture
def pooled(env):
    from test_proxlb_pins import _seed_pool_membership
    env.seed.tenant('acme', clusters=[CID])
    env.seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.backup'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    return env.api.as_user(env.seed.user('mallory', role='viewer', tenant_id='acme'))


def test_a_pool_scoped_caller_sees_their_guests_and_nothing_of_the_nodes(env, pooled):
    body = _get(pooled)
    assert body['events']
    for e in body['events']:
        assert e['guest'] == 100, e
        assert e['node'] is None or e['kind'] in ('task', 'backup', 'migration', 'balancer'), e
    kinds = {e['kind'] for e in body['events']}
    assert {'node', 'drift', 'syslog', 'incident', 'rolling_update', 'site_recovery'}.isdisjoint(kinds)
    for k in ('node', 'drift', 'syslog', 'rolling_update', 'site_recovery'):
        assert body['sources'][k]['shown'] is False, k
    text = json.dumps(body)
    assert 'db01' not in text and 'pve2 entered' not in text and 'did not boot' not in text
    # their guest's alert still links what they may see
    alert = next(e for e in body['events'] if e['id'] == 'alert:al1')
    assert {x['guest'] for x in alert['shortly_before']} == {100}


def test_a_pool_scoped_caller_gets_no_page_of_a_foreign_guest(env, pooled):
    assert pooled.get(ROUTE + '&vmid=200').status_code == 403
    assert _get(pooled, '&vmid=100')['events']


def test_the_balancer_keeps_why_from_a_confined_caller(env, pooled):
    env.db.add_migration_event(CID, 100, 'web01', 'pve1', 'pve2', 'success', reason='pve1 score 80 secret rule',
                               trigger='affinity', timestamp=_local(2))
    body = _get(pooled, '&kinds=balancer')
    assert body['events'] and all(e['details'] == '' for e in body['events'])
    admin = _get(_admin_client(env), '&kinds=balancer')
    assert any('secret rule' in e['details'] for e in admin['events'])


def test_a_standby_reads_the_timeline_from_its_active():
    from pegaprox.core import ha
    assert '/api/timeline' in ha.LEADER_ONLY_READS


def test_the_route_reads_no_fresh_guest_list_and_the_tasks_from_the_cache(env):
    _get(_admin_client(env))
    env.mgr.get_tasks.assert_called_with(limit=50)
    assert not env.mgr.get_vm_resources.called and not env.mgr.get_node_status.called


def test_a_source_that_fails_is_named_and_the_rest_still_comes(env, monkeypatch):
    import pegaprox.api.timeline as tapi
    monkeypatch.setattr(tapi, '_drift', lambda ask: 1 / 0)
    body = _get(_admin_client(env))
    assert body['sources']['drift'] == {'shown': True, 'why': 'unread', 'capped': False, 'count': 0}
    assert any(e['kind'] == 'alert' for e in body['events'])
