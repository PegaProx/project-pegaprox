"""A rolling update of a cluster enrolled in the federation goes on only while this instance
holds the cluster's lease.

Every phase of a node writes on the cluster (maintenance and evacuation, the update and its
reboot, leaving maintenance). Without the lease the run pauses with the reason
'federation_lease'; a Continue looks again and pauses again while the lease is still
missing, so a Continue never gets past the fence. The lease is asked for before each node
and again before each of its phases: one that goes in the middle of a node holds the run
before the next phase.

MK Nov 2026
"""
import pytest

from pegaprox.core import federation, rolling_runs
from test_rolling_runs_survive_restart import (CID, NODES, _a_fresh_process, _start,  # noqa: F401
                                               _until, _worker_gone, fast, root)
from test_rolling_quorum_gate import _Voting, _no_qdevice, _paused, _resume  # noqa: F401


def _held_lines(cluster):
    return sum(1 for line in rolling_runs.current(cluster)['logs']
               if 'no live federation lease' in line)


@pytest.fixture
def lease(monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    state = {'held': lambda: False}
    monkeypatch.setattr(federation, 'worker_takes_writes_for', lambda cid: state['held']())
    return state


def test_continue_does_not_pass_the_lease_hold(api, seed, db, root, fast, lease):  # noqa: F811
    cluster = api.set_manager(CID, _Voting())
    _start(api, root)
    assert _paused(cluster), rolling_runs.current(cluster)['logs']
    state = rolling_runs.current(cluster)
    assert state['paused_reason'] == 'federation_lease'
    assert state['current_step'] == 'paused_lease'
    assert ('enter', 'pve1') not in cluster.calls

    # Continue while the lease is still missing: held again, nothing was taken down
    assert _resume(api, root).status_code == 200
    assert _until(lambda: _held_lines(cluster) >= 2)
    assert _paused(cluster) and ('enter', 'pve1') not in cluster.calls

    # the lease is there: the next Continue runs the update through
    lease['held'] = lambda: True
    assert _resume(api, root).status_code == 200
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']


def test_a_lease_lost_inside_a_node_holds_its_next_phase(api, seed, db, root, fast, lease):  # noqa: F811
    cluster = api.set_manager(CID, _Voting())
    # held for the node and its maintenance, gone once pve1 is in maintenance
    lease['held'] = lambda: ('enter', 'pve1') not in cluster.calls
    _start(api, root)
    assert _paused(cluster), rolling_runs.current(cluster)['logs']
    state = rolling_runs.current(cluster)
    assert state['paused_reason'] == 'federation_lease'
    assert state['resume_at'] == {'index': 0, 'phase': 'updating'}
    assert ('enter', 'pve1') in cluster.calls and ('update', 'pve1') not in cluster.calls
    lease['held'] = lambda: True
    assert _resume(api, root).status_code == 200
    _worker_gone()
    assert rolling_runs.current(cluster)['status'] == 'completed'
    assert ('update', 'pve1') in cluster.calls


def test_the_run_asks_nothing_while_the_federation_is_off(api, seed, db, root, fast, monkeypatch):  # noqa: F811
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    asked = []
    monkeypatch.setattr(federation, 'worker_takes_writes_for', lambda cid: asked.append(cid))
    cluster = api.set_manager(CID, _Voting())
    _start(api, root)
    _worker_gone()
    assert rolling_runs.current(cluster)['status'] == 'completed' and asked == []


def test_a_reboot_refused_at_its_exit_is_no_reboot(monkeypatch):
    """The lease runs out between the upgrade and the reboot: the reboot is refused at its
    exit. The task says so and fails; it neither records a reboot nor sends the reboot
    alert, and waits for no node that never goes down."""
    import pegaprox.core.manager as mgrmod
    from pegaprox.core import ha_transport
    from pegaprox.core.manager import PegaProxManager, UpdateTask
    from test_rolling_update_reboot_953 import _FastTime, _updating_manager
    monkeypatch.setattr(mgrmod, 'time', _FastTime())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')

    def refuse(host, cmd='', again=False, cluster_id=None):
        if cmd == 'shutdown':
            raise federation.LeaseRefused('c1', f'SSH {host} shutdown')
    monkeypatch.setattr(ha_transport, 'guard_ssh', refuse)
    alerts = []
    import pegaprox.background.alerts as alerts_mod
    monkeypatch.setattr(alerts_mod, 'emit_rolling_update_reboot_event',
                        lambda *a, **k: alerts.append(a))
    m = _updating_manager(True)
    m.id = 'c1'
    m._rolling_update = {'status': 'running', 'current_node': 'blade1'}
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(m, 'blade1', task)
    assert task.status == 'failed' and 'federation lease' in (task.error or ''), task.error
    assert task.reboot_issued is False and alerts == []
