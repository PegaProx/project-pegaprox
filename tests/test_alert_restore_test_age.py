"""The restore_test_age event alert: a guest that passed no restore test within N days.

One incident per guest (object vm:<vmid>), from the guest list the tick reads anyway and
one query of restore_test_marks per cluster: never tested, the last pass too long ago, or
failing since (critical then). A test that passes closes it, a guest tagged as the rule
leaves out (and the pegaprox-verify test guests of a run) are not watched. It goes out on
every path (mail, push, webhooks), takes acks and mutes, and a confined caller sees the
incidents of its own guests only.

Driven tick by tick against the fake cluster of test_alert_events.py.
MK Oct 2026
"""
import types

import pytest

from pegaprox.background import alert_events as E
from pegaprox.core import recovery

from test_alert_events import (NOW, _Cluster, _closed, _mute, _open, _rule, _rules, _store, _who,  # noqa: F401
                               cluster, sent)
from test_ha_loop_gates import _drive, role  # noqa: F401

DAY = 86400


def _mark(vmid, ok_days=None, fail_days=None, cause='the test guest did not come up in time'):
    if ok_days is not None:
        recovery.note_result({'cluster_id': 'c1', 'vmid': vmid, 'status': 'passed', 'id': 'ok'},
                             at=NOW - ok_days * DAY)
    if fail_days is not None:
        recovery.note_result({'cluster_id': 'c1', 'vmid': vmid, 'status': 'failed', 'id': 'f',
                              'restore_ok': True, 'boot_ok': False}, at=NOW - fail_days * DAY)


def test_a_guest_without_a_recent_test_alerts_once_on_every_path_and_resolves(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restore_test_age', threshold=30))
    _mark(101, ok_days=45)
    _mark(102, ok_days=3)

    E.check_event_alerts(NOW)

    assert sent.names() == ['No recent restore test of web01 (101)']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'restore_test_age'
    assert hook['message'] == ('No restore test of web01 (101) passed in the last 30 days: the last one that '
                               'passed was 45 d ago.')
    assert hook['current_value'] == '45 days'
    assert len(sent.mail) == 1 and 'Last passed: ' in sent.mail[0][2]
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key'], row['severity']) == ('vm', '101', 'vm:101', 'warning')
    # no per-guest read of the cluster: the guest list the tick has
    assert cluster.calls == []

    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1

    _mark(101, ok_days=0)
    E.check_event_alerts(NOW + 120)
    assert sent.names()[-1] == 'Resolved: restore test of web01 (101)'
    assert sent.hooks[-1][0]['event'] == 'resolved'
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'clear'


def test_never_tested_and_failing_since(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restore_test_age', threshold=7))
    _mark(102, ok_days=20, fail_days=1)
    E.check_event_alerts(NOW)
    rows = {r['target_id']: r for r in _open(db)}
    assert set(rows) == {'101', '102'}
    assert rows['101']['severity'] == 'warning' and 'it has never been tested' in rows['101']['message']
    assert rows['102']['severity'] == 'critical'
    assert rows['102']['message'].endswith('The last test, 24 h ago, failed: the test guest did not come up in time.')


def test_tagged_out_guests_and_test_guests_are_not_watched(cluster, sent, monkeypatch, db):
    cluster.guests = [dict(cluster.guests[0], tags='no-backup'), dict(cluster.guests[1]),
                      {'vmid': 905, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'tags': 'pegaprox-verify'}]
    _rules(monkeypatch, _rule('restore_test_age', backup_exclude_tags=['no-backup']))
    E.check_event_alerts(NOW)
    assert [r['target_id'] for r in _open(db)] == ['102']
    # the tag goes on later: the incident closes without a word
    cluster.guests[1] = dict(cluster.guests[1], tags='no-backup')
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and len(sent.push) == 1


def test_a_vm_target_watches_that_guest_only(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restore_test_age', target_type='vm', target_id='102'))
    E.check_event_alerts(NOW)
    assert [r['target_id'] for r in _open(db)] == ['102']


def test_unreadable_results_change_nothing(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('restore_test_age'))
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 2

    def broken(cid):
        raise RuntimeError('database is locked')
    monkeypatch.setattr(recovery, 'load_marks', broken)
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 2 and len(sent.push) == 2
    assert E.source_status(['c1'])['c1']['restore_tests']['ok'] is False


def test_a_mute_holds_it_back_and_an_ack_keeps_it_quiet(api, seed, cluster, sent, monkeypatch, db):
    # the app harness first: it empties the manager registry the fake cluster sits in
    _rules(monkeypatch, _rule('restore_test_age'))
    _mute(db, object_key='vm:101', now=NOW)
    E.check_event_alerts(NOW)
    assert sent.names() == ['No recent restore test of db01 (102)']
    row, = _open(db)
    api.set_manager('c1', cluster)
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.post(f"/api/clusters/c1/active-alerts/{row['id']}/ack").status_code == 200
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1 and _open(db)[0]['acked_by'] == 'root'


@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_the_rule_takes_its_defaults_and_its_range(routes, monkeypatch):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'Restore tests', 'metric': 'restore_test_age'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['backup_exclude_tags']) == ('event', 30, ['no-backup'])
    for bad in (0, 366, 'month', True):
        r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'x', 'metric': 'restore_test_age', 'threshold': bad})
        assert r.status_code == 400 and 'threshold' in r.get_json()['error']
    assert len(store['c1']) == 1


def test_a_confined_caller_sees_the_incidents_of_its_guests(routes, cluster, sent, monkeypatch, db):
    from pegaprox.globals import cluster_managers
    _rules(monkeypatch, _rule('restore_test_age'))
    E.check_event_alerts(NOW)
    cluster_managers['c1'] = routes.api.make_fake_manager('c1')
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    _store(monkeypatch)
    rows = _who(routes, 'pool_confined').get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert [i['object_key'] for i in rows] == ['vm:101']
    assert _who(routes, 'other_tenant').get('/api/clusters/c1/active-alerts').status_code == 403
    assert len(routes.admin.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']) == 2


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_only_the_active_instance_evaluates_it(which, role, cluster, sent, monkeypatch, db):  # noqa: F811
    from pegaprox.background import alerts as A
    role(which)
    _rules(monkeypatch, _rule('restore_test_age'))
    for name in ('check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
                 'check_update_available_alert', '_periodic_session_cleanup', '_periodic_audit_cleanup'):
        monkeypatch.setattr(A, name, lambda *a, **k: None)
    monkeypatch.setattr(A, '_alert_running', False)
    _drive(monkeypatch, A, A.alert_check_loop)
    assert (len(_open(db)) == 2) is (which == 'active')
