# Node maintenance set through PegaProx was silently lost on every restart whenever Proxmox HA
# accepted the maintenance flag.
#
# enter_maintenance_mode() only persisted the node when task.native_ha was FALSE, on the theory
# that native HA maintenance is re-derived from PVE on each poll (#78). On PVE 9 that
# re-derivation finds nothing:
#
#   * /nodes reports status="online" for a node in HA maintenance (never "maintenance"), and
#   * /cluster/ha/status/current surfaces the flag ONLY as a type=lrm entry whose status is free
#     text — "<node> (maintenance mode, watchdog standby, <ts>)" — and there is no
#     manager_status entry at all.
#
# None of the three shapes the old parser handled (type=node + status="maintenance";
# id="manager_status" line blob; status=="maintenance" + node) appear in that payload, so it
# returned an empty set. Because it only logged when the set was non-empty, an empty parse and a
# failed poll looked identical in the log — hundreds of polls said nothing while two nodes were
# demonstrably drained.
#
# Consequence on the production cluster (2026-09-10): after a container restart PegaProx
# reported "Active nodes: 6", scored the two freshly-drained nodes as the emptiest in the cluster
# (5.53 vs 54.94) and migrated four guests straight back onto them. Draining a node makes it the
# most attractive balancer target.
#
# The payloads below are captured verbatim from the cluster (PVE 9.2.10) while pve-node-c1 and
# pve-node-c2 were in maintenance.

import logging
import threading
import types

import pytest


N21 = 'pve-node-c1'
N22 = 'pve-node-c2'


# --- captured from the cluster: GET /cluster/ha/status/current (HTTP 200) -----------------------
CAPTURED_HA_STATUS_CURRENT = [
    {"id": "quorum", "node": "pve-node-a1", "quorate": 1, "status": "OK", "type": "quorum"},
    {"id": "master", "node": "pve-node-b1", "type": "master", "timestamp": 1789062521,
     "status": "pve-node-b1 (active, Thu Sep 10 19:48:41 2026)"},
    {"armed-state": "armed", "id": "fencing", "node": "pve-node-b1", "type": "fencing",
     "status": "armed (CRM watchdog active)"},
    {"id": "lrm:pve-node-a1", "node": "pve-node-a1", "type": "lrm",
     "timestamp": 1789062525,
     "status": "pve-node-a1 (idle, watchdog standby, Thu Sep 10 19:48:45 2026)"},
    {"id": "lrm:pve-node-a2", "node": "pve-node-a2", "type": "lrm",
     "timestamp": 1789062527,
     "status": "pve-node-a2 (active, watchdog active, Thu Sep 10 19:48:47 2026)"},
    {"id": "lrm:pve-node-b1", "node": "pve-node-b1", "type": "lrm",
     "timestamp": 1789062525,
     "status": "pve-node-b1 (idle, watchdog standby, Thu Sep 10 19:48:45 2026)"},
    {"id": "lrm:pve-node-b2", "node": "pve-node-b2", "type": "lrm",
     "timestamp": 1789062525,
     "status": "pve-node-b2 (idle, watchdog standby, Thu Sep 10 19:48:45 2026)"},
    {"id": "lrm:" + N21, "node": N21, "type": "lrm", "timestamp": 1789062525,
     "status": N21 + " (maintenance mode, watchdog standby, Thu Sep 10 19:48:45 2026)"},
    {"id": "lrm:" + N22, "node": N22, "type": "lrm", "timestamp": 1789062525,
     "status": N22 + " (maintenance mode, watchdog standby, Thu Sep 10 19:48:45 2026)"},
    {"auto-rebalance": 0, "comment": "test guest", "crm_state": "started",
     "failback": 1, "id": "service:vm:100", "max_relocate": 3, "max_restart": 2,
     "node": "pve-node-a2", "request_state": "started", "sid": "vm:100",
     "state": "started", "status": "vm:100 (pve-node-a2, started)", "type": "service"},
]

# --- captured from the cluster: GET /cluster/ha/status/manager_status (HTTP 200) ----------------
CAPTURED_HA_MANAGER_STATUS = {
    "lrm_status": {
        "pve-node-a1": {"mode": "active", "results": {}, "state": "wait_for_agent_lock",
                                "timestamp": 1789062565},
        "pve-node-a2": {"mode": "active", "results": {}, "state": "active",
                                "timestamp": 1789062567},
        "pve-node-b1": {"mode": "active", "results": {}, "state": "wait_for_agent_lock",
                                "timestamp": 1789062565},
        "pve-node-b2": {"mode": "active", "results": {}, "state": "wait_for_agent_lock",
                                "timestamp": 1789062565},
        N21: {"mode": "maintenance", "results": {}, "state": "wait_for_agent_lock",
              "timestamp": 1789062565},
        N22: {"mode": "maintenance", "results": {}, "state": "wait_for_agent_lock",
              "timestamp": 1789062565},
    },
    "manager_status": {
        "master_node": "pve-node-b1",
        "node_request": {
            "pve-node-a1": {}, "pve-node-a2": {},
            "pve-node-b1": {}, "pve-node-b2": {},
            N21: {"maintenance": 1}, N22: {"maintenance": 1},
        },
        "node_status": {
            "pve-node-a1": "online", "pve-node-a2": "online",
            "pve-node-b1": "online", "pve-node-b2": "online",
            N21: "maintenance", N22: "maintenance",
        },
        "timestamp": 1789062561,
    },
    "quorum": {"node": "pve-node-a1", "quorate": "1"},
}

ALL_NODES = ['pve-node-a1', 'pve-node-a2', 'pve-node-b1',
             'pve-node-b2', N21, N22]


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def _mgr(**extra):
    """A real PegaProxManager with __init__ bypassed.

    Built with __new__ so method resolution is genuine — the code under test calls sibling
    helpers (_ha_maintenance_from_manager_status, _ha_lrm_mode_from_status, _log_ha_...) and a
    duck-typed namespace would swallow those as AttributeError and quietly take the fallback
    path. `host` and `api_port` are properties off self.config, so they are seeded there.
    """
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'cluster1'
    m.current_host = None
    m.config = types.SimpleNamespace(host='pve-node-a1.test.local',
                                     api_port=8006, excluded_nodes=[])
    m.nodes_in_maintenance = {}
    m.maintenance_lock = threading.Lock()
    m.logger = logging.getLogger('test_maint_restart')
    for k, v in extra.items():
        setattr(m, k, v)
    return m


def _api_router(routes, calls=None):
    """Serve captured payloads by endpoint suffix; 404 anything unexpected."""
    def _get(url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                if calls is not None:
                    calls.append(suffix)
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return _Resp({'data': None}, 404)
    return _get


# ---------------------------------------------------------------------------
# The parse itself — the payloads that used to yield an empty set
# ---------------------------------------------------------------------------

def test_status_current_lrm_shape_is_detected():
    """The PVE 9 type=lrm free-text shape must resolve to the two drained nodes."""
    from pegaprox.core.manager import PegaProxManager
    m = _mgr()
    m._api_get = _api_router({
        # manager_status unavailable -> exercise the status/current fallback alone
        '/cluster/ha/status/manager_status': _Resp({'data': None}, 501),
        '/cluster/ha/status/current': _Resp({'data': CAPTURED_HA_STATUS_CURRENT}),
    })
    got = PegaProxManager._get_native_ha_maintenance_nodes(m)
    assert got == {N21, N22}
    assert m._ha_maint_poll_ok is True


def test_manager_status_structured_shape_is_detected():
    from pegaprox.core.manager import PegaProxManager
    m = _mgr()
    m._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': CAPTURED_HA_MANAGER_STATUS}),
    })
    assert PegaProxManager._get_native_ha_maintenance_nodes(m) == {N21, N22}


def test_manager_status_is_preferred_and_costs_one_call():
    """The structured endpoint answers on its own — no second request per poll."""
    from pegaprox.core.manager import PegaProxManager
    calls = []
    m = _mgr()
    m._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': CAPTURED_HA_MANAGER_STATUS}),
        '/cluster/ha/status/current': _Resp({'data': CAPTURED_HA_STATUS_CURRENT}),
    }, calls)
    PegaProxManager._get_native_ha_maintenance_nodes(m)
    assert calls == ['/cluster/ha/status/manager_status']


def test_maintenance_requested_but_not_yet_applied_still_counts():
    """node_request carries {"maintenance": 1} before the CRM writes node_status."""
    from pegaprox.core.manager import PegaProxManager
    import copy
    payload = copy.deepcopy(CAPTURED_HA_MANAGER_STATUS)
    payload['manager_status']['node_status'][N21] = 'online'
    payload['lrm_status'][N21]['mode'] = 'active'
    m = _mgr()
    m._api_get = _api_router({'/cluster/ha/status/manager_status': _Resp({'data': payload})})
    assert N21 in PegaProxManager._get_native_ha_maintenance_nodes(m)


@pytest.mark.parametrize('text,expected', [
    (N21 + ' (maintenance mode, watchdog standby, Thu Sep 10 19:48:45 2026)', 'maintenance mode'),
    (N21 + ' (active, watchdog active, Thu Sep 10 19:48:47 2026)', 'active'),
    (N21 + ' (idle, watchdog standby, Thu Sep 10 19:48:45 2026)', 'idle'),
    ('armed (CRM watchdog active)', 'crm watchdog active'),
    ('', ''),
    (None, ''),
])
def test_lrm_mode_extraction(text, expected):
    from pegaprox.core.manager import PegaProxManager
    assert PegaProxManager._ha_lrm_mode_from_status(text) == expected


def test_legacy_shapes_still_parse():
    """Older PVE shapes must keep working through the status/current fallback."""
    from pegaprox.core.manager import PegaProxManager
    legacy = [
        {'type': 'node', 'node': 'pve1', 'status': 'maintenance'},
        {'id': 'manager_status', 'status': 'pve1 master\npve2 maintenance\npve3 online\n'},
        {'type': 'quorum', 'node': 'pve4', 'status': 'maintenance'},
    ]
    m = _mgr()
    m._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': None}, 501),
        '/cluster/ha/status/current': _Resp({'data': legacy}),
    })
    assert PegaProxManager._get_native_ha_maintenance_nodes(m) == {'pve1', 'pve2', 'pve4'}


# ---------------------------------------------------------------------------
# A failed poll must not read as "nobody is in maintenance"
# ---------------------------------------------------------------------------

def test_failed_poll_is_distinguishable_from_empty(caplog):
    from pegaprox.core.manager import PegaProxManager
    m = _mgr()
    m._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': None}, 401),
        '/cluster/ha/status/current': _Resp({'data': None}, 401),
    })
    with caplog.at_level(logging.DEBUG, logger='test_maint_restart'):
        assert PegaProxManager._get_native_ha_maintenance_nodes(m) == set()
    assert m._ha_maint_poll_ok is False
    assert 'UNREADABLE' in caplog.text


def test_empty_poll_is_logged_once_and_only_on_change(caplog):
    """An empty result is a real answer and must say so — but must not spam every poll."""
    from pegaprox.core.manager import PegaProxManager
    empty = dict(CAPTURED_HA_MANAGER_STATUS)
    empty = {'lrm_status': {n: {'mode': 'active'} for n in ALL_NODES},
             'manager_status': {'node_status': {n: 'online' for n in ALL_NODES},
                                'node_request': {n: {} for n in ALL_NODES}}}
    m = _mgr()
    m._api_get = _api_router({'/cluster/ha/status/manager_status': _Resp({'data': empty})})
    with caplog.at_level(logging.INFO, logger='test_maint_restart'):
        for _ in range(5):
            assert PegaProxManager._get_native_ha_maintenance_nodes(m) == set()
    assert caplog.text.count('no nodes in native maintenance') == 1

    # ...and a transition into maintenance is announced
    caplog.clear()
    m._api_get = _api_router({'/cluster/ha/status/manager_status':
                              _Resp({'data': CAPTURED_HA_MANAGER_STATUS})})
    with caplog.at_level(logging.INFO, logger='test_maint_restart'):
        PegaProxManager._get_native_ha_maintenance_nodes(m)
        PegaProxManager._get_native_ha_maintenance_nodes(m)
    assert caplog.text.count('nodes in native maintenance') == 1
    assert N21 in caplog.text and N22 in caplog.text


# ---------------------------------------------------------------------------
# The actual bug: enter -> restart -> still in maintenance, and not a target
# ---------------------------------------------------------------------------

def _enter_maintenance(db, monkeypatch, node, native_ha_succeeds):
    """Run the real enter_maintenance_mode() against a stubbed cluster."""
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)

    evacuated = []

    def _try_native(node_name, task):
        if native_ha_succeeds:
            task.native_ha = True
        return native_ha_succeeds

    m = _mgr()
    m._set_ceph_maintenance_flags = lambda n: {'present': False, 'flags_set': False, 'error': None}
    m._try_native_ha_maintenance = _try_native
    m._evacuate_node = lambda n, t: evacuated.append(n)
    task = PegaProxManager.enter_maintenance_mode(m, node)
    return m, task


def test_native_ha_maintenance_is_persisted(db, monkeypatch):
    """The regression: an accepted native HA flag used to skip the DB write entirely."""
    m, task = _enter_maintenance(db, monkeypatch, N21, native_ha_succeeds=True)
    assert task.native_ha is True
    rows = db.get_node_maintenance('cluster1')
    assert [(n, ha) for n, _ts, ha in rows] == [(N21, True)]


def test_soft_maintenance_is_still_persisted(db, monkeypatch):
    m, task = _enter_maintenance(db, monkeypatch, N21, native_ha_succeeds=False)
    assert task.native_ha is False
    rows = db.get_node_maintenance('cluster1')
    assert [(n, ha) for n, _ts, ha in rows] == [(N21, False)]


def test_maintenance_survives_restart_and_node_is_not_a_target(db, monkeypatch):
    """enter (native HA accepted) -> restart -> still in maintenance, still not a target."""
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)

    _enter_maintenance(db, monkeypatch, N21, native_ha_succeeds=True)
    _enter_maintenance(db, monkeypatch, N22, native_ha_succeeds=True)

    # --- restart: brand-new manager, empty in-memory state ---
    fresh = _mgr()
    PegaProxManager._restore_persisted_maintenance(fresh)

    assert set(fresh.nodes_in_maintenance) == {N21, N22}
    # native_ha must come back too, or exit_maintenance_mode would never clear the PVE flag
    assert fresh.nodes_in_maintenance[N21].native_ha is True
    assert fresh.nodes_in_maintenance[N22].native_ha is True

    # the balancer must not pick a drained node, even though it now scores as the emptiest.
    # maintenance_mode mirrors the daemon's own derivation (manager.py: node in
    # nodes_in_maintenance) — the drained nodes carry the LOWEST scores, as on the cluster.
    scores = {'pve-node-a1': 30.17, 'pve-node-a2': 54.94,
              'pve-node-b1': 30.53, 'pve-node-b2': 20.23,
              N21: 5.53, N22: 7.14}
    fresh.get_node_status = lambda: {
        n: {'status': 'online', 'score': s, 'maintenance_mode': n in fresh.nodes_in_maintenance}
        for n, s in scores.items()
    }

    target = PegaProxManager.get_best_target_node(fresh)
    assert target not in (N21, N22)
    assert target == 'pve-node-b2'   # the emptiest node that is actually available


def test_restored_entry_is_not_dropped_by_the_next_poll(db, monkeypatch):
    """Restored rows must outlive a poll that reports nothing in HA maintenance.

    Only entries DISCOVERED by refresh are auto-removed; a restored one is ours until the user
    exits. On the cluster this matters because PVE can clear the LRM flag while guests are still on
    the node.
    """
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)

    _enter_maintenance(db, monkeypatch, N21, native_ha_succeeds=True)

    fresh = _mgr()
    PegaProxManager._restore_persisted_maintenance(fresh)
    assert N21 in fresh.nodes_in_maintenance
    assert getattr(fresh.nodes_in_maintenance[N21], '_discovered_by_refresh', False) is False

    # a poll that finds nobody in HA maintenance
    empty = {'lrm_status': {n: {'mode': 'active'} for n in ALL_NODES},
             'manager_status': {'node_status': {n: 'online' for n in ALL_NODES},
                                'node_request': {n: {} for n in ALL_NODES}}}
    fresh._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': empty}),
        '/nodes': _Resp({'data': [{'node': n, 'status': 'online'} for n in ALL_NODES]}),
    })
    PegaProxManager.refresh_maintenance_status(fresh)
    assert N21 in fresh.nodes_in_maintenance


def test_unreadable_poll_does_not_evict_a_discovered_node():
    """A 401 must not look like 'maintenance is over' to the cleanup pass."""
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.models.tasks import MaintenanceTask

    fresh = _mgr()
    t = MaintenanceTask(N21)
    t.native_ha = True
    t._discovered_by_refresh = True
    fresh.nodes_in_maintenance[N21] = t

    fresh._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': None}, 401),
        '/cluster/ha/status/current': _Resp({'data': None}, 401),
        '/nodes': _Resp({'data': [{'node': n, 'status': 'online'} for n in ALL_NODES]}),
    })
    PegaProxManager.refresh_maintenance_status(fresh)
    assert N21 in fresh.nodes_in_maintenance

    # but a readable poll that genuinely reports nothing DOES clear it
    empty = {'lrm_status': {n: {'mode': 'active'} for n in ALL_NODES},
             'manager_status': {'node_status': {n: 'online' for n in ALL_NODES},
                                'node_request': {n: {} for n in ALL_NODES}}}
    fresh._api_get = _api_router({
        '/cluster/ha/status/manager_status': _Resp({'data': empty}),
        '/nodes': _Resp({'data': [{'node': n, 'status': 'online'} for n in ALL_NODES]}),
    })
    PegaProxManager.refresh_maintenance_status(fresh)
    assert N21 not in fresh.nodes_in_maintenance


def test_exit_clears_the_persisted_row(db, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)

    _enter_maintenance(db, monkeypatch, N21, native_ha_succeeds=True)

    fresh = _mgr()
    PegaProxManager._restore_persisted_maintenance(fresh)
    disabled = []
    fresh._try_disable_native_ha_maintenance = lambda n: disabled.append(n) or True
    fresh._unset_ceph_maintenance_flags = lambda n: None

    assert PegaProxManager.exit_maintenance_mode(fresh, N21) is True
    # the restored entry knew it was native HA, so the upstream flag was cleared
    assert disabled == [N21]
    assert fresh.nodes_in_maintenance == {}
    assert db.get_node_maintenance('cluster1') == []
