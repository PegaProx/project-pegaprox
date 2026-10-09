"""Event alerts: failed Proxmox tasks, Ceph health, replication and stale snapshots.

The engine (pegaprox/background/alert_events.py) is driven tick by tick against a fake
cluster that answers the API paths it reads, with the throwaway database holding the
incidents and the mutes. What leaves goes through alerts.dispatch_alert and is recorded
at its three exits: email, the notification handlers (push and inbox) and the webhook
channels - an alert source that reaches one of them and not the others is the #815 bug.

The routes at the end are driven through the real app: the rule fields, the mutes and
who may touch them.
MK Oct 2026
"""
import json
import time
import types

import pytest

from pegaprox.background import alert_events as E
from pegaprox.background import alerts as A


# --- a cluster that answers ------------------------------------------------------------

class _Resp:
    def __init__(self, code, data):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


class _Cluster:
    host, api_port, is_connected, cluster_type = 'pve.example', 8006, True, 'proxmox'

    def __init__(self, guests=None, name='Testi'):
        self.config = types.SimpleNamespace(name=name)
        self.paths = {}
        self.calls = []
        self.guests = list(guests if guests is not None else
                           [{'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'name': 'web01'},
                            {'vmid': 102, 'type': 'lxc', 'node': 'pve2', 'name': 'db01'}])
        self.nodes = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}

    def answer(self, path, data, code=200):
        self.paths[path] = (code, data)

    def _api_get(self, url, timeout=10):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        hit = self.paths.get(path)
        if hit is None:
            return _Resp(404, None)
        if isinstance(hit, Exception):
            raise hit
        return _Resp(*hit)

    def get_vm_resources(self, max_age=0):
        return list(self.guests)

    def get_node_status(self):
        return dict(self.nodes)

    def count(self, path):
        return self.calls.count(path)


NOW = 1_790_000_000.0


def _task(upid, ttype='vzdump', node='pve1', tid='101', end=NOW - 60, status='job errors'):
    return {'upid': upid, 'node': node, 'type': ttype, 'id': tid, 'starttime': end - 30,
            'endtime': end, 'status': status, 'user': 'root@pam'}


@pytest.fixture
def cluster(db, monkeypatch):
    from pegaprox.globals import cluster_managers
    for name in ('_tasks', '_ceph', '_repl', '_snaps', '_status'):
        monkeypatch.setattr(E, name, {})
    monkeypatch.setattr(E, '_last_prune', [0.0])
    c = _Cluster()
    cluster_managers['c1'] = c
    yield c
    cluster_managers.pop('c1', None)


@pytest.fixture
def sent(monkeypatch):
    """Everything that left, at each of the three exits."""
    out = types.SimpleNamespace(mail=[], push=[], hooks=[])
    monkeypatch.setattr(A, '_notification_handlers', [lambda d: out.push.append(d)])
    import pegaprox.utils.webhooks as webhooks
    monkeypatch.setattr(webhooks, 'send_to_channels',
                        lambda d, channel_ids=None: out.hooks.append((d, channel_ids)))
    monkeypatch.setattr(A, 'send_email', lambda to, subject, body, html: out.mail.append(
        (to, subject, body, html)) or (True, None))
    import pegaprox.api.helpers as helpers
    real = helpers.load_server_settings
    monkeypatch.setattr(helpers, 'load_server_settings',
                        lambda: dict(real() or {}, alert_email_recipients=['ops@example.com']))
    out.names = lambda: [d['alert_name'] for d in out.push]
    return out


def _rules(monkeypatch, *rules):
    store = {'alerts': [dict(r) for r in rules], 'enabled': True}
    monkeypatch.setattr(A, 'load_alerts_config', lambda: store)
    return store['alerts']


def _rule(metric='task_failed', rid='r1', **kw):
    r = {'id': rid, 'name': f'{metric} rule', 'cluster_id': 'c1', 'metric': metric,
         'operator': 'event', 'threshold': E._THRESHOLDS[metric][0], 'enabled': True,
         'channels': ['email', 'hook1'], 'target_type': 'cluster', 'target_id': None,
         'notify_resolved': True, 'severity': 'auto'}
    if metric == 'task_failed':
        r.update(task_type='vzdump', task_status='', task_warnings=False)
    if metric == 'snapshot_age':
        r['snapshot_ignore_policy'] = True
    r.update(kw)
    return r


def _open(db, rid=None):
    q = "SELECT * FROM active_alerts WHERE resolved_at IS NULL"
    rows = [dict(r) for r in db.conn.execute(q).fetchall()]
    return [r for r in rows if rid is None or r['alert_id'] == rid]


def _closed(db):
    return [dict(r) for r in db.conn.execute(
        "SELECT * FROM active_alerts WHERE resolved_at IS NOT NULL").fetchall()]


def _mute(db, rule_id='', object_key='', minutes=60, cluster_id='c1', now=None):
    until = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime((now or time.time()) + minutes * 60))
    db.conn.execute(
        "INSERT INTO alert_mutes (id, cluster_id, rule_id, object_key, until, created_at) "
        "VALUES (?,?,?,?,?,?)", (f'm{time.monotonic_ns()}', cluster_id, rule_id, object_key, until,
                                 '2026-10-04T00:00:00'))
    db.conn.commit()


# --- failed tasks ----------------------------------------------------------------------

def test_a_failed_backup_alerts_once_on_every_path(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1'), _task('U0', ttype='qmstart', status='OK')])

    E.check_event_alerts(NOW)

    assert sent.names() == ['Backup of web01 (101) failed']
    assert [s for _, s, _, _ in sent.mail] == ['[PegaProx Alert] Backup of web01 (101) failed']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['alert_name'] == 'Backup of web01 (101) failed'
    assert hook['event'] == 'firing' and hook['cluster_id'] == 'c1' and hook['current_value'] == 'job errors'
    assert 'pve1' in hook['message'] and 'job errors' in hook['message']
    row, = _open(db, 'r1')
    assert row['target_type'] == 'vm' and row['target_id'] == '101'
    assert row['object_key'] == 'task:pve1:vzdump:101' and row['operator'] == 'event'

    # the next polls see the same failure: nothing more goes out
    for i in range(1, 4):
        E.check_event_alerts(NOW + 60 * i)
    assert len(sent.push) == len(sent.hooks) == len(sent.mail) == 1
    assert len(_open(db, 'r1')) == 1


def test_the_next_successful_run_resolves_it(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/tasks', [_task('U2', end=NOW + 50, status='OK'), _task('U1')])

    E.check_event_alerts(NOW + 60)

    assert sent.names() == ['Backup of web01 (101) failed', 'Resolved: Backup of web01 (101)']
    assert sent.hooks[-1][0]['event'] == 'resolved' and sent.hooks[-1][0]['severity'] == 'info'
    assert sent.mail[-1][1] == '[PegaProx] Resolved: Backup of web01 (101)'
    assert _open(db) == []
    assert _closed(db)[0]['resolved_by'] == 'clear'


def test_without_notify_resolved_the_incident_closes_quietly(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule(notify_resolved=False))
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/tasks', [_task('U2', end=NOW + 50, status='OK')])
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['Backup of web01 (101) failed']
    assert _open(db) == []


def test_a_node_wide_backup_job_is_about_the_node(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1', tid='', node='pve2')])
    E.check_event_alerts(NOW)
    assert sent.names() == ['Backup on pve2 failed']
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key']) == ('node', 'pve2', 'task:pve2:vzdump:')


def test_the_status_pattern_picks_the_failures(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule(task_status='job errors'))
    cluster.answer('/cluster/tasks', [_task('U1', status='unexpected status'),
                                      _task('U2', tid='102', node='pve2', status='job errors')])
    E.check_event_alerts(NOW)
    assert sent.names() == ['Backup of db01 (102) failed']
    # a failure it does not ask about clears nothing either
    cluster.answer('/cluster/tasks', [_task('U3', tid='102', node='pve2', end=NOW + 10,
                                            status='unexpected status')])
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 1 and len(sent.push) == 1


@pytest.mark.parametrize('warnings,alerted', [(False, False), (True, True)])
def test_warnings_count_only_when_the_rule_says_so(cluster, sent, monkeypatch, db, warnings, alerted):
    _rules(monkeypatch, _rule(task_warnings=warnings))
    cluster.answer('/cluster/tasks', [_task('U1', status='WARNINGS: 2')])
    E.check_event_alerts(NOW)
    assert bool(sent.push) == alerted


def test_the_type_pattern_and_the_target(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule(task_type='qm(start|migrate)', target_type='node', target_id='pve2'))
    cluster.answer('/cluster/tasks', [_task('U1', ttype='qmstart', node='pve1'),
                                      _task('U2', ttype='qmmigrate', node='pve2', tid='102'),
                                      _task('U3', ttype='qmstartx', node='pve2', tid='102'),
                                      _task('U4', ttype='vzdump', node='pve2', tid='102')])
    E.check_event_alerts(NOW)
    assert sent.names() == ['qmmigrate of db01 (102) failed']


def test_a_restart_does_not_say_it_again(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    # a new process: the cursors are gone, the open incident is not
    for name in ('_tasks', '_ceph', '_repl', '_snaps', '_status'):
        monkeypatch.setattr(E, name, {})
    E.check_event_alerts(NOW + 120)
    assert len(sent.push) == 1


def test_an_old_failure_is_not_reported_on_first_sight(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1', end=NOW - E.TASK_LOOKBACK - E.TASK_OVERLAP - 10)])
    E.check_event_alerts(NOW)
    assert sent.push == []


def test_one_task_list_read_per_cluster_and_tick(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule(rid='r1'), _rule(rid='r2', task_type='qm.*'),
           _rule('snapshot_age', rid='r3'))
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + 60)
    assert cluster.count('/cluster/tasks') == 2


def test_a_cluster_that_is_not_connected_says_so(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.is_connected = False
    E.check_event_alerts(NOW)
    assert cluster.calls == [] and sent.push == []
    assert 'not connected' in A._last_eval['r1']['reason']


def test_a_running_task_is_neither_failure_nor_success(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    running = {'upid': 'U2', 'node': 'pve1', 'type': 'vzdump', 'id': '101', 'starttime': NOW + 10}
    cluster.answer('/cluster/tasks', [running, _task('U1')])
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 1 and len(sent.push) == 1


def test_a_guest_list_that_failed_closes_no_task_incident(cluster, sent, monkeypatch, db):
    """get_vm_resources answers [] when the read fails: that is not every guest gone."""
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    cluster.guests = []
    cluster.answer('/cluster/tasks', [_task('U9', ttype='qmstart', status='OK', end=NOW + 30)])
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 1
    # counterproof: with the guest list read and the guest really gone, it closes quietly
    cluster.guests = [{'vmid': 102, 'type': 'lxc', 'node': 'pve2', 'name': 'db01'}]
    E.check_event_alerts(NOW + 120)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone' and len(sent.push) == 1


def test_an_unreadable_task_list_changes_nothing(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/tasks', None, code=500)
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 1 and len(sent.push) == 1


# --- mutes -----------------------------------------------------------------------------

def test_a_rule_mute_holds_it_back_until_it_runs_out(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    _mute(db, rule_id='r1', minutes=30, now=NOW)
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    assert sent.push == [] and sent.hooks == [] and sent.mail == [] and _open(db) == []
    assert A._last_eval['r1']['muted'] == 1
    # still failing once the mute is over: now it is said
    E.check_event_alerts(NOW + 31 * 60)
    assert sent.names() == ['Backup of web01 (101) failed']


def test_an_object_mute_holds_back_that_guest_under_every_rule(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    _mute(db, object_key='vm:101', now=NOW)
    cluster.answer('/cluster/tasks', [_task('U1'), _task('U2', tid='102', node='pve2')])
    E.check_event_alerts(NOW)
    assert sent.names() == ['Backup of db01 (102) failed']


def test_a_mute_of_another_cluster_or_rule_does_not_count(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    _mute(db, rule_id='r1', cluster_id='c2', now=NOW)
    _mute(db, rule_id='other', now=NOW)
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    assert len(sent.push) == 1


def test_a_muted_resolve_says_nothing(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    _mute(db, rule_id='r1', now=NOW)
    cluster.answer('/cluster/tasks', [_task('U2', end=NOW + 30, status='OK')])
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1 and _open(db) == []


def test_mute_matching():
    m = [{'cluster_id': 'c1', 'rule_id': 'r1', 'object_key': '', 'until': '2099-01-01T00:00:00'},
         {'cluster_id': 'c1', 'rule_id': '', 'object_key': 'node:pve1', 'until': '2099-01-02T00:00:00'},
         {'cluster_id': 'c1', 'rule_id': 'r2', 'object_key': 'task:pve2:vzdump:', 'until': '2099-01-03T00:00:00'},
         {'cluster_id': 'c1', 'rule_id': '', 'object_key': '', 'until': '2099-01-04T00:00:00'}]
    assert E.mute_for(m, 'c1', 'r1', 'vm:5')['rule_id'] == 'r1'
    assert E.mute_for(m, 'c1', 'r9', 'task:pve1:qmstart:', 'node:pve1')['object_key'] == 'node:pve1'
    assert E.mute_for(m, 'c1', 'r2', 'task:pve2:vzdump:')['rule_id'] == 'r2'
    assert E.mute_for(m, 'c1', 'r3', 'task:pve2:vzdump:') is None     # that mute names r2
    assert E.mute_for(m, 'c1', 'r9', 'vm:7') is None                   # the empty one mutes nothing
    assert E.mute_for(m, 'c2', 'r1', 'vm:5') is None
    # the longest wins
    both = E.mute_for(m, 'c1', 'r1', 'node:pve1')
    assert both['until'] == '2099-01-02T00:00:00'


def test_expired_mutes_are_ignored_and_pruned_once_an_hour(db, monkeypatch):
    monkeypatch.setattr(E, '_last_prune', [0.0])
    _mute(db, rule_id='r1', minutes=-5)
    _mute(db, rule_id='r1', minutes=-3 * 24 * 60)
    _mute(db, rule_id='r2', minutes=60)
    assert [m['rule_id'] for m in E.active_mutes('c1')] == ['r2']
    E.prune_mutes()
    assert db.conn.execute('SELECT COUNT(*) FROM alert_mutes').fetchone()[0] == 2
    _mute(db, rule_id='r3', minutes=-3 * 24 * 60)
    E.prune_mutes()
    assert db.conn.execute('SELECT COUNT(*) FROM alert_mutes').fetchone()[0] == 3
    # a DELETE that matched nothing still opened a write transaction: nothing may be
    # left open holding the write lock for the next writer
    monkeypatch.setattr(E, '_last_prune', [0.0])
    db.conn.commit()
    E.prune_mutes()
    assert db.conn.in_transaction is False


# --- Ceph ------------------------------------------------------------------------------

def _ceph(state, checks=None):
    return {'health': {'status': state, 'checks': checks or {}}}


def test_ceph_warn_then_err_then_ok(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_WARN', {
        'OSD_DOWN': {'severity': 'HEALTH_WARN', 'summary': {'message': '1 osds down'}}}))
    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['Ceph HEALTH_WARN on Testi']
    assert 'OSD_DOWN: 1 osds down' in sent.push[0]['message'] and sent.push[0]['severity'] == 'warning'

    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_ERR', {
        'PG_DAMAGED': {'severity': 'HEALTH_ERR', 'summary': {'message': 'Possible data damage'}}}))
    E.check_event_alerts(NOW + 120)
    assert sent.names()[-1] == 'Ceph on Testi is now HEALTH_ERR'
    assert sent.push[-1]['severity'] == 'critical'
    row, = _open(db)
    assert row['current_value'] == 2.0 and row['severity'] == 'critical'

    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_OK'))
    E.check_event_alerts(NOW + 180)
    assert sent.names()[-1] == 'Resolved: Ceph on Testi'
    assert _open(db) == [] and len(sent.push) == 3


def test_an_err_only_rule_waits_for_err(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health', threshold=1))
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_WARN'))
    E.check_event_alerts(NOW)
    assert sent.push == []
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_ERR'))
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['Ceph HEALTH_ERR on Testi']


def test_a_cluster_without_ceph_is_asked_again_only_later(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', None, code=500)
    E.check_event_alerts(NOW)
    first = len(cluster.calls)
    # the API host and two probed nodes
    assert cluster.count('/cluster/ceph/status') == 1
    assert cluster.count('/nodes/pve1/ceph/status') == cluster.count('/nodes/pve2/ceph/status') == 1
    E.check_event_alerts(NOW + 60)
    E.check_event_alerts(NOW + 120)
    assert len(cluster.calls) == first
    E.check_event_alerts(NOW + E.CEPH_RETRY + 1)
    assert cluster.count('/cluster/ceph/status') == 2


def test_ceph_answers_from_a_node_when_the_api_host_has_none(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', None, code=500)
    cluster.answer('/nodes/pve2/ceph/status', _ceph('HEALTH_WARN'))
    E.check_event_alerts(NOW)
    assert sent.names() == ['Ceph HEALTH_WARN on Testi']
    E.check_event_alerts(NOW + 60)
    # the node that answered is asked first from now on, the others not at all
    assert cluster.count('/nodes/pve1/ceph/status') == 1


def test_ceph_that_stops_answering_keeps_its_incident_and_is_asked_again(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_ERR'))
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/ceph/status', None, code=500)
    E.check_event_alerts(NOW + 60)
    E.check_event_alerts(NOW + 120)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    assert cluster.count('/cluster/ceph/status') == 3


# --- replication -----------------------------------------------------------------------

def _jobs(*jobs):
    return [dict({'type': 'local', 'schedule': '*/15'}, **j) for j in jobs]


def test_replication_failing_behind_and_back_in_sync(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication', threshold=30))
    cluster.answer('/cluster/replication', _jobs(
        {'id': '101-0', 'guest': 101, 'target': 'pve2', 'source': 'pve1'},
        {'id': '102-0', 'guest': 102, 'target': 'pve1', 'source': 'pve2'}))
    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 3, 'error': 'no space left',
                                                'last_sync': NOW - 7200}])
    cluster.answer('/nodes/pve2/replication', [{'id': '102-0', 'fail_count': 0, 'last_sync': NOW - 3600}])
    E.check_event_alerts(NOW)
    assert sorted(sent.names()) == ['Replication 101-0 of web01 (101) is failing',
                                    'Replication 102-0 of db01 (102) is behind']
    sev = {d['alert_name']: d['severity'] for d in sent.push}
    assert sev['Replication 101-0 of web01 (101) is failing'] == 'critical'
    assert 'no space left' in next(d['message'] for d in sent.push if 'failing' in d['alert_name'])

    # not due yet: nothing is read
    reads = len(cluster.calls)
    E.check_event_alerts(NOW + 60)
    assert cluster.calls[reads:] == []

    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 0, 'last_sync': NOW + 290}])
    cluster.answer('/nodes/pve2/replication', [{'id': '102-0', 'fail_count': 0, 'last_sync': NOW + 290}])
    E.check_event_alerts(NOW + E.REPLICATION_EVERY + 1)
    assert sorted(sent.names()[2:]) == ['Resolved: replication 101-0', 'Resolved: replication 102-0']
    assert _open(db) == []


def test_a_source_node_that_does_not_answer_leaves_its_jobs_alone(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication', threshold=30))
    cluster.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'target': 'pve2',
                                                  'source': 'pve1'}))
    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 1, 'error': 'boom',
                                                'last_sync': NOW - 60}])
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1
    cluster.answer('/nodes/pve1/replication', None, code=595)
    E.check_event_alerts(NOW + E.REPLICATION_EVERY + 1)
    assert len(_open(db)) == 1 and len(sent.push) == 1


def test_nodes_past_the_time_budget_stay_unknown(cluster, sent, monkeypatch, db):
    """One node after the other inside REPLICATION_BUDGET: what is left unread is unknown,
    so a slow cluster neither raises nor clears anything for those jobs."""
    _rules(monkeypatch, _rule('replication', threshold=30))
    cluster.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'target': 'pve2',
                                                  'source': 'pve1'}))
    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 1, 'error': 'x'}])
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1
    monkeypatch.setattr(E, 'REPLICATION_BUDGET', -1)
    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 0, 'last_sync': NOW + 300}])
    before = cluster.count('/nodes/pve1/replication')
    E.check_event_alerts(NOW + E.REPLICATION_EVERY + 1)
    assert cluster.count('/nodes/pve1/replication') == before      # not asked at all
    assert len(_open(db)) == 1 and len(sent.push) == 1
    assert 'unread' in E.source_status()['c1']['replication']['note']


def test_a_removed_job_closes_its_incident_quietly(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication', threshold=30))
    cluster.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'target': 'pve2',
                                                  'source': 'pve1'}))
    cluster.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 1, 'error': 'x'}])
    E.check_event_alerts(NOW)
    cluster.answer('/cluster/replication', [])
    E.check_event_alerts(NOW + E.REPLICATION_EVERY + 1)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone'
    assert len(sent.push) == 1


def test_jobs_without_a_source_yet_ask_every_online_node(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication'))
    cluster.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'target': 'pve2'}))
    cluster.answer('/nodes/pve1/replication', [])
    cluster.answer('/nodes/pve2/replication', [])
    E.check_event_alerts(NOW)
    assert cluster.count('/nodes/pve1/replication') == cluster.count('/nodes/pve2/replication') == 1
    assert sent.push == [] and _open(db) == []


# --- snapshots -------------------------------------------------------------------------

def _snapshots(*items):
    return [{'name': n, 'snaptime': ts} for n, ts in items] + [{'name': 'current'}]


def test_snapshot_ages_are_read_once_then_after_a_snapshot_task_only(cluster, sent, monkeypatch, db):
    monkeypatch.setattr(E, 'SNAPSHOT_READS_PER_TICK', 1)
    _rules(monkeypatch, _rule('snapshot_age', threshold=14))
    cluster.answer('/cluster/tasks', [])
    cluster.answer('/nodes/pve1/qemu/101/snapshot', _snapshots(('before-upgrade', NOW - 40 * 86400)))
    cluster.answer('/nodes/pve2/lxc/102/snapshot', _snapshots(('fresh', NOW - 3600)))

    E.check_event_alerts(NOW)
    # one guest per tick here; nothing is said before every guest was read once
    assert cluster.count('/nodes/pve1/qemu/101/snapshot') == 1
    assert cluster.count('/nodes/pve2/lxc/102/snapshot') == 0 and sent.push == []
    E.check_event_alerts(NOW + 60)
    assert cluster.count('/nodes/pve2/lxc/102/snapshot') == 1
    assert sent.names() == ['Old snapshots on web01 (101)']
    assert "'before-upgrade'" in sent.push[0]['message'] and '40 days' in sent.push[0]['message']

    for i in range(2, 6):
        E.check_event_alerts(NOW + 60 * i)
    assert cluster.count('/nodes/pve1/qemu/101/snapshot') == 1
    assert cluster.count('/nodes/pve2/lxc/102/snapshot') == 1

    # the snapshot is deleted: the task shows up, that one guest is read again
    cluster.answer('/nodes/pve1/qemu/101/snapshot', _snapshots())
    cluster.answer('/cluster/tasks', [_task('D1', ttype='qmdelsnapshot', end=NOW + 330, status='OK')])
    E.check_event_alerts(NOW + 360)
    assert cluster.count('/nodes/pve1/qemu/101/snapshot') == 2
    assert cluster.count('/nodes/pve2/lxc/102/snapshot') == 1
    assert sent.names()[-1] == 'Resolved: old snapshots on web01 (101)'
    assert _open(db) == []


def test_policy_snapshots_are_ignored_unless_asked(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('snapshot_age', rid='skip'),
           _rule('snapshot_age', rid='all', snapshot_ignore_policy=False))
    cluster.answer('/cluster/tasks', [])
    cluster.answer('/nodes/pve1/qemu/101/snapshot', _snapshots(('pegaprox-abc-20260801', NOW - 60 * 86400)))
    cluster.answer('/nodes/pve2/lxc/102/snapshot', _snapshots())
    E.check_event_alerts(NOW)
    assert [r['alert_id'] for r in _open(db)] == ['all']


def test_a_guest_that_left_closes_its_incident_quietly(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('snapshot_age'))
    cluster.answer('/cluster/tasks', [])
    cluster.answer('/nodes/pve1/qemu/101/snapshot', _snapshots(('old', NOW - 99 * 86400)))
    cluster.answer('/nodes/pve2/lxc/102/snapshot', _snapshots())
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1
    cluster.guests = [g for g in cluster.guests if g['vmid'] != 101]
    E.check_event_alerts(NOW + E.SNAPSHOT_EVAL_EVERY + 1)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone'
    assert len(sent.push) == 1


def test_an_empty_guest_list_is_not_taken_as_every_guest_gone(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('snapshot_age'))
    cluster.answer('/cluster/tasks', [])
    cluster.answer('/nodes/pve1/qemu/101/snapshot', _snapshots(('old', NOW - 99 * 86400)))
    cluster.answer('/nodes/pve2/lxc/102/snapshot', _snapshots())
    E.check_event_alerts(NOW)
    cluster.guests = []          # get_vm_resources answers [] on a failed read too
    E.check_event_alerts(NOW + E.SNAPSHOT_EVAL_EVERY + 1)
    assert len(_open(db)) == 1


# --- volume and lifecycle --------------------------------------------------------------

def test_a_burst_is_capped_with_one_summary(cluster, sent, monkeypatch, db):
    cluster.guests = [{'vmid': 200 + i, 'type': 'qemu', 'node': 'pve1', 'name': f'g{i}'} for i in range(30)]
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task(f'U{i}', tid=str(200 + i)) for i in range(30)])
    E.check_event_alerts(NOW)
    assert len(sent.push) == E.NOTICES_PER_RULE + 1
    assert sent.names()[-1] == 'task_failed rule: 10 more alerts'
    assert len(sent.hooks) == len(sent.mail) == E.NOTICES_PER_RULE + 1
    # every condition is recorded, so none of them comes back as new
    assert len(_open(db)) == 30
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == E.NOTICES_PER_RULE + 1


def test_a_rule_switched_off_or_moved_closes_its_incidents_quietly(cluster, sent, monkeypatch, db):
    rules = _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    rules[0]['enabled'] = False
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'rule'
    assert len(sent.push) == 1


def test_the_lifecycle_leaves_event_incidents_to_their_rule(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    db.conn.execute("UPDATE active_alerts SET last_fired_at='2020-01-01T00:00:00'")
    db.conn.commit()
    A.process_alert_lifecycle()
    assert len(_open(db)) == 1


def test_an_event_incident_escalates_like_any_other(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule(escalation=[{'after_minutes': 1, 'channels': ['pager']}]))
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    db.conn.execute("UPDATE active_alerts SET triggered_at='2020-01-01T00:00:00'")
    db.conn.commit()
    A.process_alert_lifecycle()
    assert sent.hooks[-1][1] == ['pager'] and '[escalation 1]' in sent.hooks[-1][0]['alert_name']


def test_a_muted_incident_does_not_escalate(cluster, sent, monkeypatch, db):
    """Muting a firing incident from the list is how it is silenced: the escalation chain
    must hold still like it does for an ack, and go on once the mute is lifted."""
    _rules(monkeypatch, _rule(escalation=[{'after_minutes': 1, 'channels': ['pager']}]))
    cluster.answer('/cluster/tasks', [_task('U1')])
    E.check_event_alerts(NOW)
    db.conn.execute("UPDATE active_alerts SET triggered_at='2020-01-01T00:00:00'")
    db.conn.commit()
    _mute(db, object_key='vm:101')
    hooks = len(sent.hooks)
    A.process_alert_lifecycle()
    assert len(sent.hooks) == hooks
    # counterproof: the mute lifted, the same incident escalates
    db.conn.execute('DELETE FROM alert_mutes')
    db.conn.commit()
    A.process_alert_lifecycle()
    assert sent.hooks[-1][1] == ['pager']


def test_a_muted_ceph_rule_says_nothing_when_it_gets_worse(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_WARN'))
    E.check_event_alerts(NOW)
    _mute(db, rule_id='r1', now=NOW)
    cluster.answer('/cluster/ceph/status', _ceph('HEALTH_ERR'))
    E.check_event_alerts(NOW + 60)
    assert sent.names() == ['Ceph HEALTH_WARN on Testi']
    assert _open(db)[0]['current_value'] == 2.0      # the incident still follows what Ceph says


# --- the metric rules get mute and the resolved note -----------------------------------

def _metric_cluster(cpu):
    from unittest.mock import MagicMock
    m = MagicMock()
    m.get_node_summary.return_value = {'cpu': cpu}
    m.config.name = 'Testi'
    return m


def test_a_muted_metric_rule_sends_nothing(db, sent, monkeypatch):
    from pegaprox.globals import cluster_managers
    rule = {'id': 'cpu1', 'name': 'CPU', 'cluster_id': 'c1', 'metric': 'cpu', 'operator': '>',
            'threshold': 50, 'target_type': 'node', 'target_id': 'pve1', 'channels': ['hook1'],
            'enabled': True}
    _rules(monkeypatch, rule)
    monkeypatch.setitem(cluster_managers, 'c1', _metric_cluster(0.9))
    monkeypatch.setattr(A, '_alert_last_sent', {})
    _mute(db, object_key='node:pve1')
    A.check_and_send_alerts()
    assert sent.hooks == [] and sent.push == []
    assert A._last_eval['cpu1']['reason'].startswith('muted until')
    db.conn.execute('DELETE FROM alert_mutes')
    db.conn.commit()
    A.check_and_send_alerts()
    assert len(sent.hooks) == len(sent.push) == 1


@pytest.mark.parametrize('notify', [True, False])
def test_a_metric_rule_that_asks_hears_its_incident_is_over(db, sent, monkeypatch, notify):
    rule = {'id': 'cpu1', 'name': 'CPU high', 'cluster_id': 'c1', 'metric': 'cpu', 'operator': '>',
            'threshold': 50, 'target_type': 'node', 'target_id': 'pve1', 'channels': ['hook1'],
            'enabled': True, 'notify_resolved': notify}
    _rules(monkeypatch, rule)
    A._upsert_active_alert('cpu1:c1:node:pve1:cpu', 'cpu1', {
        'cluster_id': 'c1', 'metric': 'cpu', 'target_type': 'node', 'target_name': 'pve1',
        'severity': 'warning', 'message': 'Node pve1: cpu is 90%'}, 90, 50, '>', 'pve1')
    db.conn.execute("UPDATE active_alerts SET last_fired_at='2020-01-01T00:00:00'")
    db.conn.commit()
    A.process_alert_lifecycle()
    assert _open(db) == []
    if notify:
        assert sent.names() == ['Resolved: CPU high']
        assert sent.push[0]['message'] == 'Node pve1: cpu is no longer > 50%'
        assert sent.hooks[0][1] == ['hook1']
    else:
        assert sent.push == [] and sent.hooks == []


# --- patterns --------------------------------------------------------------------------

@pytest.mark.parametrize('pattern', ['vzdump', 'qm.*|vz.*', '.*error.*', 'job errors|unexpected',
                                     '^vz(dump|migrate)$', '(?:qm)?start', '[a-z]+ failed'])
def test_patterns_people_write_are_taken(pattern):
    assert E.check_pattern(pattern)


@pytest.mark.parametrize('pattern', ['(a+)+b', '(ab|cd)*', r'(a)\1', '.*.*.*x', '(x*y)*', '[', 'a' * 121,
                                     '(?:a|aa)+$'])
def test_patterns_that_can_hold_up_the_loop_are_refused(pattern):
    with pytest.raises(ValueError):
        E.check_pattern(pattern)


def test_what_is_refused_would_really_take_long_and_what_is_taken_does_not():
    import re
    slow = re.compile('.*.*.*.*x')
    t = time.monotonic()
    slow.search('a' * 120)
    assert time.monotonic() - t > 0.05, 'the counterproof pattern got fast - pick another'
    ok = E.check_pattern('.*error.*')
    t = time.monotonic()
    ok.search('a' * E.SUBJECT_MAX)
    assert time.monotonic() - t < 0.05


# --- the routes ------------------------------------------------------------------------

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


def test_an_event_rule_is_pinned_and_takes_its_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    for metric, threshold in (('task_failed', 1), ('ceph_health', 0), ('replication', 60), ('snapshot_age', 14)):
        r = routes.admin.post('/api/clusters/c1/alerts', json={'name': metric, 'metric': metric})
        assert r.status_code == 200, r.data
        rule = r.get_json()['alert']
        assert rule['operator'] == 'event' and rule['threshold'] == threshold, rule
        assert rule['notify_resolved'] is True
    task = store['c1'][0]
    assert task['task_type'] == 'vzdump' and task['task_status'] == '' and task['task_warnings'] is False
    assert store['c1'][3]['snapshot_ignore_policy'] is True
    # a CPU rule keeps its comparison and does not ask for a resolved note by itself
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'cpu', 'metric': 'cpu', 'threshold': 90})
    assert r.get_json()['alert']['operator'] == '>' and 'notify_resolved' not in r.get_json()['alert']


@pytest.mark.parametrize('body,needle', [
    ({'metric': 'task_failed', 'task_type': '(a+)+'}, 'task type'),
    ({'metric': 'task_failed', 'task_status': '['}, 'exit status'),
    ({'metric': 'replication', 'threshold': 0}, 'threshold'),
    ({'metric': 'snapshot_age', 'threshold': 'soon'}, 'threshold'),
    ({'metric': 'snapshot_age', 'target_type': 'vm', 'target_id': 'web01'}, 'numeric'),
    ({'metric': 'task_failed', 'target_type': 'node'}, 'node name'),
])
def test_a_bad_event_rule_is_refused(routes, monkeypatch, body, needle):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json=dict(body, name='x'))
    assert r.status_code == 400 and needle in r.get_json()['error'], r.data
    assert store['c1'] == []


def test_a_ceph_rule_is_always_about_the_cluster(routes, monkeypatch):
    _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={
        'name': 'c', 'metric': 'ceph_health', 'target_type': 'node', 'target_id': 'pve1', 'threshold': 1})
    rule = r.get_json()['alert']
    assert rule['target_type'] == 'cluster' and rule['target_id'] is None and rule['threshold'] == 1


def test_editing_what_a_rule_matches_starts_it_over(routes, monkeypatch, db):
    store = _store(monkeypatch, [_rule()])
    store['c1'][0]['id'] = 'r1'
    db.conn.execute("INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, object_key, "
                    "triggered_at) VALUES ('x1', 'r1:c1:o', 'r1', 'c1', 'task_failed', 'o', '2026-10-01')")
    db.conn.commit()
    # a new name does not
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'name': 'Nightly'}).status_code == 200
    assert len(_open(db)) == 1
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'task_type': 'vzdump|qmrestore'})
    assert r.status_code == 200 and r.get_json()['alert']['task_type'] == 'vzdump|qmrestore'
    assert _open(db) == []


def test_switching_an_event_rule_to_a_metric_restores_a_comparison(routes, monkeypatch):
    store = _store(monkeypatch, [_rule()])
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'metric': 'memory'})
    rule = store['c1'][0]
    assert r.status_code == 200 and rule['operator'] == '>' and rule['threshold'] == 80
    assert 'task_type' not in rule


def test_a_switched_off_rule_comes_back_with_the_list(routes, db):
    """The list read only enabled rows: a rule switched off vanished on reload, and the PUT
    that would switch it on again could not find it."""
    from pegaprox.api import alerts as am
    am.save_cluster_alerts({'c1': [dict(_rule(), id='r1')]})
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'enabled': False}).status_code == 200
    listed = routes.admin.get('/api/clusters/c1/alerts').get_json()['alerts']
    assert [(a['id'], a['enabled']) for a in listed] == [('r1', False)]
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'enabled': True}).status_code == 200
    assert routes.admin.get('/api/clusters/c1/alerts').get_json()['alerts'][0]['enabled'] is True
    # the background loop reads the column as it always did
    assert [a['enabled'] for a in A.load_alerts_config()['alerts']] == [True]


def _incident(db, rid='r1', obj='task:pve1:vzdump:101', ttype='vm', tid='101', name='web01 (101)'):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, severity, message, triggered_at, last_fired_at, object_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f'i-{obj}', f'{rid}:c1:{obj}', rid, 'c1', 'task_failed', ttype, tid, name, 'warning',
         'Backup failed', '2026-10-04T01:00:00', '2026-10-04T01:00:00', obj))
    db.conn.commit()
    return f'i-{obj}'


def test_a_mute_picked_from_an_incident(routes, monkeypatch, db):
    _store(monkeypatch, [_rule()])
    fired = _incident(db)
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': fired, 'minutes': 60})
    assert r.status_code == 200, r.data
    mute = r.get_json()['mute']
    assert (mute['rule_id'], mute['object_key'], mute['object_label']) == ('r1', 'task:pve1:vzdump:101',
                                                                           'web01 (101)')
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': fired, 'minutes': 60,
                                                                'whole_object': True})
    assert (r.get_json()['mute']['rule_id'], r.get_json()['mute']['object_key']) == ('', 'vm:101')

    rows = routes.admin.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert rows[0]['object_key'] == 'task:pve1:vzdump:101' and rows[0]['muted_until']
    listed = routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']
    assert len(listed) == 2

    assert routes.admin.delete(f"/api/clusters/c1/alert-mutes/{mute['id']}").status_code == 200
    assert routes.admin.delete(f"/api/clusters/c1/alert-mutes/{mute['id']}").status_code == 404
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 1

    actions = [r[0] for r in db.conn.execute(
        "SELECT action FROM audit_log WHERE action LIKE 'alert.%'").fetchall()]
    assert actions.count('alert.muted') == 2 and actions.count('alert.unmuted') == 1


def test_a_metric_incident_is_muted_by_its_target(routes, monkeypatch, db):
    _store(monkeypatch, [{'id': 'cpu1', 'name': 'CPU', 'metric': 'cpu', 'cluster_id': 'c1'}])
    fired = _incident(db, rid='cpu1', obj='', ttype='node', tid='pve1', name='pve1')
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': fired, 'minutes': 5})
    assert r.get_json()['mute']['object_key'] == 'node:pve1'


@pytest.mark.parametrize('body,code', [
    ({'minutes': 60}, 400),
    ({'rule_id': 'r1', 'minutes': 0}, 400),
    ({'rule_id': 'r1', 'minutes': E.MUTE_MAX_MINUTES + 1}, 400),
    ({'rule_id': 'r1', 'minutes': True}, 400),
    ({'rule_id': 'nope', 'minutes': 60}, 404),
    ({'active_alert_id': 'nope', 'minutes': 60}, 404),
    ({'object_key': 'x' * 201, 'minutes': 60}, 400),
])
def test_a_bad_mute_is_refused(routes, monkeypatch, db, body, code):
    _store(monkeypatch, [_rule()])
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json=body)
    assert r.status_code == code, r.data
    assert db.conn.execute('SELECT COUNT(*) FROM alert_mutes').fetchone()[0] == 0


def test_a_cluster_wide_incident_cannot_be_muted_as_an_object(routes, monkeypatch, db):
    _store(monkeypatch, [_rule('ceph_health')])
    fired = _incident(db, obj='ceph', ttype='cluster', tid='', name='Testi')
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': fired, 'minutes': 5,
                                                                'whole_object': True})
    assert r.status_code == 400


def test_deleting_a_rule_takes_its_mutes(routes, monkeypatch, db):
    from pegaprox.api import alerts as am
    am.save_cluster_alerts({'c1': [dict(_rule(), id='r1')]})
    _mute(db, rule_id='r1')
    _mute(db, object_key='vm:101')
    assert routes.admin.delete('/api/clusters/c1/alerts/r1').status_code == 200
    assert [m['object_key'] for m in E.active_mutes('c1')] == ['vm:101']


def _who(routes, kind):
    seed, api = routes.seed, routes.api
    if kind == 'operator':
        # the tenant owns the cluster, no pool, no ACL: a cluster-wide operator
        seed.tenant('t_own', ['c1'])
        return api.as_user(seed.user('op', role='user', tenant_id='t_own', permissions=['cluster.config']))
    if kind == 'no_permission':
        seed.tenant('t_own', ['c1'])
        return api.as_user(seed.user('plain', role='user', tenant_id='t_own'))
    if kind == 'pool_confined':
        # reaches the cluster through a pool grant only
        seed.tenant('t_confined', [])
        seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
        return api.as_user(seed.user('pooled', role='user', tenant_id='t_confined',
                                     permissions=['cluster.config']))
    if kind == 'capped_admin':
        seed.tenant('globex', ['c_globex'])
        return api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                     tenant_permissions={'globex': {'role': 'user'}}))
    if kind == 'other_tenant':
        seed.tenant('acme', ['c2'])
        return api.as_user(seed.user('acme_op', role='user', tenant_id='acme', permissions=['cluster.config']))
    raise AssertionError(kind)


@pytest.mark.parametrize('kind,read,write', [
    ('operator', 200, 200),
    ('no_permission', 200, 403),
    ('pool_confined', 200, 403),
    ('capped_admin', 403, 403),
    ('other_tenant', 403, 403),
])
def test_who_may_list_set_and_lift_a_mute(routes, monkeypatch, db, kind, read, write):
    _store(monkeypatch, [_rule()])
    _mute(db, rule_id='r1')
    mute_id = E.active_mutes('c1')[0]['id']
    c = _who(routes, kind)
    assert c.get('/api/clusters/c1/alert-mutes').status_code == read
    r = c.post('/api/clusters/c1/alert-mutes', json={'rule_id': 'r1', 'minutes': 30})
    assert r.status_code == write, (kind, r.data)
    r = c.delete(f'/api/clusters/c1/alert-mutes/{mute_id}')
    assert r.status_code == write, (kind, r.data)
    ids = [row[0] for row in db.conn.execute('SELECT id FROM alert_mutes').fetchall()]
    if write == 200:
        assert len(ids) == 1 and mute_id not in ids          # one made, the old one lifted
    else:
        assert ids == [mute_id]                               # neither
    audited = db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'alert.%muted'").fetchone()[0]
    assert audited == (2 if write == 200 else 0)


def test_a_confined_caller_sees_only_mutes_of_guests_it_sees(routes, monkeypatch, db):
    _store(monkeypatch, [_rule(), dict(_rule(rid='rv'), target_type='vm', target_id='300')])
    _mute(db, object_key='vm:101')
    _mute(db, object_key='replication:300-0')
    _mute(db, rule_id='rv')
    _mute(db, rule_id='r1')
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    c = _who(routes, 'pool_confined')
    keys = sorted((m['rule_id'], m['object_key']) for m in c.get('/api/clusters/c1/alert-mutes').get_json()['mutes'])
    assert keys == [('', 'vm:101'), ('r1', '')]
    # counterproof: the admin sees all four
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 4


def test_a_confined_caller_sees_no_mute_of_a_node_object(routes, monkeypatch, db):
    _store(monkeypatch, [_rule()])
    _mute(db, object_key='vm:101')
    _mute(db, object_key='node:pve2')
    _mute(db, object_key='task:pve2:aptupdate:')
    _mute(db, object_key='zfs:pve2:tank')
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    c = _who(routes, 'pool_confined')
    keys = [m['object_key'] for m in c.get('/api/clusters/c1/alert-mutes').get_json()['mutes']]
    assert keys == ['vm:101']
    # counterproof: the admin sees the node objects too
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 4


def test_a_standby_refuses_mute_writes(routes, monkeypatch, db):
    from pegaprox.core import ha
    _store(monkeypatch, [_rule()])
    peer = {'instance_id': 'a' * 32, 'url': 'https://active.example:5000', 'fingerprint': '',
            'secret_out': 'y' * 43, 'secret_in_hash': ha._hash_secret('z' * 50),
            'paired_at': '2026-09-29T10:00:00+00:00', 'role_seen': 'active', 'epoch_seen': 1}
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump({'role': 'standby', 'epoch': 1, 'instance_id': 'b' * 32, 'interval': 30,
                   'peer': peer, 'pairing': None, 'sync': {}, 'forward_writes': False}, fh)
    ha.reset_for_tests()
    assert ha.is_standby()
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json={'rule_id': 'r1', 'minutes': 30})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = routes.admin.delete('/api/clusters/c1/alert-mutes/whatever')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert db.conn.execute('SELECT COUNT(*) FROM alert_mutes').fetchone()[0] == 0
    # reading stays local: the table is synced
    assert routes.admin.get('/api/clusters/c1/alert-mutes').status_code == 200


def test_the_mute_table_is_shared_configuration():
    from pegaprox.core import ha
    assert 'alert_mutes' in ha.SYNC_TABLES and 'alert_mutes' not in ha.LOCAL_TABLES
    assert 'active_alerts' in ha.LOCAL_TABLES


def test_the_diagnostics_say_what_the_sources_saw(routes, monkeypatch, db, cluster, sent):
    _rules(monkeypatch, _rule())
    cluster.answer('/cluster/tasks', [])
    E.check_event_alerts(NOW)
    diag = routes.admin.get('/api/alerts/diagnostics').get_json()
    assert diag['event_sources']['c1']['tasks']['ok'] is True
    # another tenant's operator sees none of it
    c = _who(routes, 'other_tenant')
    c_diag = c.get('/api/alerts/diagnostics')
    if c_diag.status_code == 200:
        assert 'c1' not in c_diag.get_json()['event_sources']
