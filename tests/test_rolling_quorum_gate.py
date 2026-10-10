"""The quorum gate of a rolling update.

The run only logged 'quorum HELD / AT RISK' at its start, from a count of the nodes. Now,
before each node goes into maintenance and before its update, it reads /cluster/status, the
votes of corosync.conf and the QDevice, and goes on only when the cluster stays quorate with
that node down. Otherwise it pauses with the reason 'quorum' (rolling_runs.change, the _hold
of the worker); Continue looks again, Continue anyway takes that one node down all the same,
Cancel ends the run. A scheduled run pauses the same way and hands the run to the worker of
a run started by hand on Continue.

Without the gate the runs below walk straight into maintenance with a node of a three-node
cluster already down (test_a_node_already_down_holds_the_run_before_maintenance fails on
its first assert).

MK Oct 2026
"""
import json
import time

import pytest

import pegaprox.globals as g
from pegaprox.core import qdevice, rolling_runs
from test_rolling_runs_survive_restart import (CID, NODES, _a_fresh_process, _Cluster, _start,  # noqa: F401
                                               _until, _worker_gone, fast, root)


def _status(online=None, quorate=1, names=('pve1', 'pve2', 'pve3')):
    online = set(names if online is None else online)
    return ([{'type': 'cluster', 'name': 'lab', 'quorate': quorate, 'nodes': len(names)}]
            + [{'type': 'node', 'name': n, 'online': int(n in online), 'ip': f'10.0.0.{i + 1}'}
               for i, n in enumerate(names)])


class _Voting(_Cluster):
    """The cluster of the restart tests with a /cluster/status of its own."""

    def __init__(self, status=..., votes=None, **kw):
        super().__init__(**kw)
        # None: /cluster/status does not answer
        self.cluster_status = _status() if status is ... else status
        self.votes = votes or {}
        self.status_reads = 0

    def _ha_cluster_status(self):
        self.status_reads += 1
        status = self.cluster_status() if callable(self.cluster_status) else self.cluster_status
        return [dict(e) for e in status] if status is not None else None


@pytest.fixture(autouse=True)
def _no_qdevice(monkeypatch):
    seen = {'view': None}
    monkeypatch.setattr(qdevice, 'view', lambda cid, mgr, *a, **k: seen['view'])
    monkeypatch.setattr(rolling_runs, '_config_votes', lambda mgr: dict(getattr(mgr, 'votes', {}) or {}))
    return seen


def _facts(status, votes=None, qd=None, two_node=False, monkeypatch=None):
    m = _Voting(status=status, votes=votes)
    m.ha_config = {'fence_strategy': {'two_node_flag': two_node}}
    if qd is not None:
        monkeypatch.setattr(qdevice, 'view', lambda cid, mgr, *a, **k: qd)
    return rolling_runs.quorum_facts(m)


# -- the arithmetic ----------------------------------------------------------------------------

def test_three_nodes_keep_their_quorum_with_one_down():
    v = rolling_runs.quorum_without(_facts(_status()), 'pve1')
    assert v['ok'] and (v['expected'], v['needed'], v['have'], v['after']) == (3, 2, 3, 2)


def test_three_nodes_with_one_already_down_lose_it_with_a_second():
    v = rolling_runs.quorum_without(_facts(_status(online=('pve1', 'pve2'))), 'pve1')
    assert not v['ok'] and v['reason'] == 'would_lose'
    assert (v['after'], v['needed'], v['offline']) == (1, 2, ['pve3'])
    # the node that is down itself is no further loss
    v = rolling_runs.quorum_without(_facts(_status(online=('pve1', 'pve2'))), 'pve3')
    assert v['ok'] and v['after'] == 2


def test_two_nodes_with_a_connected_qdevice_keep_it(monkeypatch):
    qd = {'present': True, 'state': 'Connected', 'algorithm': 'Fast Semi-Split'}
    v = rolling_runs.quorum_without(_facts(_status(names=('pve1', 'pve2')), qd=qd, monkeypatch=monkeypatch), 'pve1')
    assert v['ok'] and (v['expected'], v['needed'], v['after']) == (3, 2, 2)
    assert v['qdevice'] == {'present': True, 'connected': True}


def test_two_nodes_whose_qdevice_lost_its_qnetd_do_not(monkeypatch):
    qd = {'present': True, 'state': 'Disconnected', 'algorithm': 'Fast Semi-Split'}
    v = rolling_runs.quorum_without(_facts(_status(names=('pve1', 'pve2')), qd=qd, monkeypatch=monkeypatch), 'pve2')
    assert not v['ok'] and (v['expected'], v['needed'], v['after']) == (3, 2, 1)
    assert 'QDevice NOT connected' in rolling_runs.quorum_said(v)


def test_two_nodes_without_a_qdevice_lose_it_unless_corosync_runs_two_node():
    v = rolling_runs.quorum_without(_facts(_status(names=('pve1', 'pve2'))), 'pve1')
    assert not v['ok'] and (v['expected'], v['needed'], v['after']) == (2, 2, 1)
    v = rolling_runs.quorum_without(_facts(_status(names=('pve1', 'pve2')), two_node=True), 'pve1')
    assert v['ok'] and v['needed'] == 1


def test_an_lms_qdevice_carries_one_vote_less_than_the_nodes(monkeypatch):
    qd = {'present': True, 'state': 'Connected', 'algorithm': 'LMS'}
    names = ('a', 'b', 'c', 'd')
    v = rolling_runs.quorum_without(_facts(_status(online=('a', 'b'), names=names), qd=qd,
                                           monkeypatch=monkeypatch), 'a')
    # 4 + 3 votes, 4 needed: b and the QDevice still hold it
    assert v['ok'] and (v['expected'], v['needed'], v['after']) == (7, 4, 4)


def test_the_votes_of_corosync_conf_count():
    # pve1 carries two votes: without it 2 of 4 remain, 3 needed
    v = rolling_runs.quorum_without(_facts(_status(), votes={'pve1': 2}), 'pve1')
    assert not v['ok'] and (v['expected'], v['needed'], v['after']) == (4, 3, 2)
    assert rolling_runs.quorum_without(_facts(_status(), votes={'pve1': 2}), 'pve2')['ok']


def test_not_quorate_unreadable_standalone_and_xcpng():
    v = rolling_runs.quorum_without(_facts(_status(quorate=0)), 'pve1')
    assert not v['ok'] and v['reason'] == 'not_quorate'
    v = rolling_runs.quorum_without(_facts(None), 'pve1')
    assert not v['ok'] and v['reason'] == 'status_unreadable'
    single = [{'type': 'node', 'name': 'pve1', 'online': 1}]
    assert rolling_runs.quorum_without(_facts(single), 'pve1') == {
        'ok': True, 'reason': None, 'node': 'pve1', 'standalone': True, 'offline': []}
    xcp = _Voting()
    xcp.cluster_type = 'xcpng'
    assert rolling_runs.quorum_facts(xcp) is None
    assert rolling_runs.quorum_without(None, 'h1')['ok']


def test_a_verdict_against_is_looked_at_again_before_the_run_holds():
    states = iter([_status(online=('pve1', 'pve2')), _status(online=('pve1', 'pve2')), _status()])
    m = _Voting(status=lambda: next(states))
    slept = []
    v = rolling_runs.quorum_gate(m, 'pve1', sleep=slept.append)
    assert v['ok'] and slept == [rolling_runs.QUORUM_LOOK_EVERY] * 2
    # never longer than the settle time, and not past the end of the run
    m = _Voting(status=_status(online=('pve1', 'pve2')))
    slept = []
    assert not rolling_runs.quorum_gate(m, 'pve1', sleep=slept.append)['ok']
    assert sum(slept) == rolling_runs.QUORUM_SETTLE
    slept = []
    assert not rolling_runs.quorum_gate(m, 'pve1', sleep=slept.append, stop=lambda: True)['ok'] and slept == []


# -- the run -----------------------------------------------------------------------------------

def _row(db):
    row = db.get_rolling_runs(CID)[0]
    return dict(row, state=json.loads(row['state']), logs=json.loads(row['logs']))


def _paused(cluster):
    return _until(lambda: (rolling_runs.current(cluster) or {}).get('status') == 'paused')


def _resume(api, root, body=None):  # noqa: F811
    kw = {'json': body} if body is not None else {}
    return api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling/resume', **kw)


def test_a_three_node_cluster_with_all_nodes_up_runs_through(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting())
    _start(api, root)
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']
    logs = '\n'.join(state['logs'])
    assert 'Quorum with pve1 down: 2 of 3 votes, 2 needed' in logs
    # before maintenance and before the update, per node
    assert cluster.status_reads == 2 * len(NODES)


def test_a_node_already_down_holds_the_run_before_maintenance(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting(status=_status(online=('pve1', 'pve2'))))
    _start(api, root)
    assert _paused(cluster), rolling_runs.current(cluster)['logs']
    state = rolling_runs.current(cluster)
    assert state['paused_reason'] == 'quorum' and state['current_step'] == 'paused_quorum'
    d = state['paused_details']
    assert (d['node'], d['phase'], d['reason'], d['after'], d['expected'], d['needed'], d['offline']) == (
        'pve1', 'maintenance', 'would_lose', 1, 3, 2, ['pve3'])
    assert 'taking pve1 down would leave 1 of 3 votes, and the cluster needs 2 (pve3 offline)' in d['message']
    assert state['resume_at'] == {'index': 0, 'phase': 'maintenance'}
    assert ('enter', 'pve1') not in cluster.calls, 'nothing was taken down'
    assert _row(db)['state']['paused_reason'] == 'quorum'

    # Continue looks again: still down, so it holds again
    r = _resume(api, root)
    assert r.status_code == 200 and r.get_json()['was_paused_for'] == 'quorum'
    assert _until(lambda: any('looking at the quorum again' in line for line in rolling_runs.current(cluster)['logs']))
    assert _paused(cluster) and ('enter', 'pve1') not in cluster.calls

    # pve3 is back: the next Continue goes on and the run ends
    cluster.cluster_status = _status()
    assert _resume(api, root).status_code == 200
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']
    audit = db.conn.execute("SELECT details FROM audit_log WHERE action = 'node.rolling_update_resumed'").fetchall()
    assert len(audit) == 2 and 'was paused: quorum' in audit[0][0]


def test_continue_anyway_takes_that_one_node_down(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting(status=_status(online=('pve1', 'pve2'))))
    _start(api, root)
    assert _paused(cluster)
    r = _resume(api, root, {'accept_quorum_risk': True})
    assert r.status_code == 200, r.get_json()
    # pve1 goes, and pve2 is held again: the risk was taken for one node
    assert _until(lambda: ('update', 'pve1') in cluster.calls)
    assert _until(lambda: (rolling_runs.current(cluster).get('paused_details') or {}).get('node') == 'pve2')
    state = rolling_runs.current(cluster)
    assert state['status'] == 'paused' and state['quorum_risk_accepted'] == ['pve1']
    assert any('going on, the risk was accepted for pve1' in line for line in state['logs'])
    assert ('enter', 'pve2') not in cluster.calls
    audit = db.conn.execute("SELECT details FROM audit_log WHERE action = 'node.rolling_update_resumed'").fetchone()[0]
    assert 'the quorum risk accepted for pve1' in audit
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_continue_anyway_is_for_a_quorum_hold_only_and_bodies_are_checked(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting())
    cluster.start_node_update = lambda node, reboot=False, force=False: None   # pauses with node_failure
    _start(api, root)
    assert _paused(cluster)
    assert rolling_runs.current(cluster)['paused_reason'] == 'node_failure'
    r = _resume(api, root, {'accept_quorum_risk': True})
    assert r.status_code == 400 and 'quorum' in r.get_json()['error']
    for bad in ({'accept_quorum_risk': 'yes'}, {'accept_quorum_risk': 1}, ['x']):
        assert _resume(api, root, bad).status_code == 400, bad
    assert rolling_runs.current(cluster)['status'] == 'paused'
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_a_node_that_drops_out_during_the_evacuation_holds_the_update(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting())
    orig = cluster.enter_maintenance_mode

    def enter(node, **kw):
        # pve3 goes down while pve1 is emptied
        cluster.cluster_status = _status(online=('pve1', 'pve2'))
        return orig(node, **kw)
    cluster.enter_maintenance_mode = enter
    _start(api, root)
    assert _paused(cluster)
    state = rolling_runs.current(cluster)
    assert state['paused_details']['phase'] == 'updating' and state['resume_at'] == {'index': 0, 'phase': 'updating'}
    assert ('update', 'pve1') not in cluster.calls and state['node_state']['pve1']['in_maintenance'] is True
    # Cancel: the node comes out of maintenance, nothing is updated
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200
    _worker_gone()
    assert rolling_runs.current(cluster)['status'] == 'cancelled'
    assert ('exit', 'pve1') in cluster.calls and ('update', 'pve1') not in cluster.calls


def test_two_nodes_with_a_qdevice_run_through(api, seed, db, root, fast, _no_qdevice):  # noqa: F811
    _no_qdevice['view'] = {'present': True, 'state': 'Connected', 'algorithm': 'Fast Semi-Split'}
    cluster = api.set_manager(CID, _Voting(status=_status(names=NODES)))
    _start(api, root)
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed', state['logs']
    assert any('2 of 3 votes, 2 needed, QDevice connected' in line for line in state['logs'])


def test_a_restart_while_held_looks_again_on_continue(api, seed, db, root, fast, monkeypatch):  # noqa: F811
    from pegaprox.core import ha
    cluster = api.set_manager(CID, _Voting(status=_status(online=('pve1', 'pve2'))))
    _start(api, root)
    assert _paused(cluster)
    waiting = rolling_runs._live[CID]['thread']
    # a new process: the run is in the table, paused, and no worker waits for it
    rolling_runs.reset_for_tests()
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    fresh = _Voting()
    rolling_runs.restore(fresh)
    assert rolling_runs.current(fresh)['paused_reason'] == 'quorum'
    api.set_manager(CID, fresh)
    assert _resume(api, root).status_code == 200
    _worker_gone()
    state = rolling_runs.current(fresh)
    assert state['status'] == 'completed', state['logs']
    assert fresh.calls[:2] == [('enter', 'pve1'), ('update', 'pve1')]
    # the "old process" worker still waits in this one: let it go
    rolling_runs.change(cluster, status='cancelled')
    waiting.join(10)


def test_a_scheduled_run_pauses_and_continue_hands_it_to_the_worker(api, seed, db, root, monkeypatch):  # noqa: F811
    import pegaprox.api.schedules as sch
    import pegaprox.api.settings as st
    from test_rolling_runs_survive_restart import _FastTime
    monkeypatch.setattr(sch, 'time', _FastTime())
    monkeypatch.setattr(st, 'time', _FastTime())
    cluster = api.set_manager(CID, _Voting(status=_status(online=('pve1', 'pve2'))))
    sch.execute_scheduled_rolling_update(cluster, CID, {'config': {'include_reboot': False,
                                                                    'skip_up_to_date': False}})
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'paused' and state['paused_reason'] == 'quorum', state['logs']
    assert state['resume_at'] == {'index': 0, 'phase': 'maintenance'}
    assert ('enter', 'pve1') not in cluster.calls
    assert _row(db)['status'] == 'paused'
    cluster.cluster_status = _status()
    assert g.cluster_managers[CID] is cluster
    assert _resume(api, root).status_code == 200
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']


def test_the_paused_reason_reaches_the_status_route(api, seed, db, root, fast):  # noqa: F811
    cluster = api.set_manager(CID, _Voting(status=_status(quorate=0)))
    _start(api, root)
    assert _paused(cluster)
    body = api.as_user(root).get(f'/api/clusters/{CID}/updates/status').get_json()
    run = body['rolling_update']
    assert run['paused_reason'] == 'quorum' and run['paused_details']['reason'] == 'not_quorate'
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_the_gate_waits_no_longer_than_its_settle_time():
    assert rolling_runs.QUORUM_SETTLE <= 120 and rolling_runs.QUORUM_LOOK_EVERY <= rolling_runs.QUORUM_SETTLE
    # the start logs it was looked at: nothing is per guest, a constant number of reads per node
    started = time.time()
    m = _Voting(status=_status(names=tuple(f'n{i:03d}' for i in range(100))))
    assert rolling_runs.quorum_gate(m, 'n000', sleep=lambda s: None)['ok']
    assert m.status_reads == 1 and time.time() - started < 1
