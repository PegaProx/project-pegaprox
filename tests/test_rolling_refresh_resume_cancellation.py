"""A resumed rolling update must stop if its package refresh is cancelled."""
from pegaprox.core import rolling_runs
from test_rolling_runs_survive_restart import (CID, _Cluster, _die, _restart, _worker_gone,
                                              root, fast)  # noqa: F401 (fixtures)


def test_cancel_during_resumed_refresh_cannot_start_update(api, seed, db, root, fast, monkeypatch):
    """Cancel after recovering an interrupted update with maintenance still held."""
    _die(api, root, db, ('updating', 'pve1'))
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',))),
                     monkeypatch=monkeypatch)

    def cancel_during_refresh(node):
        """The refresh completes after cancellation; the recovered update must not restart."""
        rolling_runs.change(fresh, status='cancelled')
        return {'success': True, 'task': None}

    monkeypatch.setattr(fresh, 'refresh_node_apt', cancel_during_refresh)
    response = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling/resume')
    assert response.status_code == 200, response.data
    _worker_gone()
    assert ('update', 'pve1') not in fresh.calls, fresh.calls
