"""Auto-failover must not fire because a cluster was removed from PegaProx.

_heartbeat_check read `cluster_managers.get(source_cluster)` and folded a missing
manager into the same src_reachable=False as a manager that exists but can't
reach its site. Deleting the source cluster — or leaving a plan pointing at an id
that no longer exists — therefore looked exactly like a site outage, and
failover_timeout seconds later the heartbeat started every replica at the DR site
while production was serving traffic. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.api.site_recovery as sr_api
import pegaprox.background.site_recovery as sr
import pegaprox.globals as ppglobals


PROD, DR = 'cluster_prod', 'cluster_dr'


@pytest.fixture
def heartbeat(monkeypatch):
    """Record emergency failovers instead of running them, and start from clean trackers."""
    fired = []
    # the heartbeat imports the spawn wrapper from the api module at call time
    monkeypatch.setattr(sr_api, '_safe_spawn_failover', lambda fn, *a, **kw: fired.append(a))
    def _reset():
        sr._last_fail_times.clear()
        sr._cooldowns.clear()
        # tolerated so these still run against a tree without the held-plan tracker, and
        # fail on the behaviour rather than on the attribute
        getattr(sr, '_missing_source_logged', set()).clear()
        ppglobals.cluster_managers.clear()

    _reset()
    try:
        yield fired
    finally:
        _reset()


@pytest.fixture
def plan(db):
    def _make(source=PROD):
        db.execute(
            "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, "
            "target_cluster, status, auto_failover, failover_timeout) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ('plan_1', 'g1', 'DR Plan', source, DR, 'ready', 1, 0))
        # a healthy replication job, or the separate pre-failover health gate blocks the
        # trigger and the outage tests would pass for the wrong reason
        db.execute(
            "INSERT INTO cross_cluster_replications "
            "(id, source_cluster, target_cluster, vmid, enabled, last_status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ('repl_1', source, DR, 100, 1, 'ok'))
        db.execute(
            "INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type, boot_group, "
            "replication_job_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ('vm_row_1', 'plan_1', 100, 'app-01', 'qemu', 0, 'repl_1'))
        return 'plan_1'
    return _make


def _connected(cid, connected=True):
    m = MagicMock()
    m.is_connected = connected
    m.config.name = cid
    ppglobals.cluster_managers[cid] = m
    return m


def test_removed_source_cluster_does_not_arm_the_countdown(db, plan, heartbeat):
    """The whole point: no manager means no evidence either way, so hold."""
    plan_id = plan()
    _connected(DR)                       # only the DR side is still configured

    sr._heartbeat_check()
    sr._heartbeat_check()                # failover_timeout is 0, so a second pass would fire

    assert heartbeat == [], 'auto-failover fired on a cluster that was merely unconfigured'
    assert plan_id not in sr._last_fail_times


def test_a_configured_but_disconnected_source_still_counts_as_an_outage(db, plan, heartbeat):
    """The behaviour we must not lose: a real outage still arms and fires."""
    plan_id = plan()
    _connected(PROD, connected=False)
    _connected(DR)

    sr._heartbeat_check()
    assert plan_id in sr._last_fail_times, 'a real outage must arm the countdown'

    sr._heartbeat_check()
    assert heartbeat, 'a real outage must still trigger auto-failover'


def test_a_healthy_source_clears_the_tracker(db, plan, heartbeat):
    plan_id = plan()
    _connected(PROD)
    _connected(DR)
    sr._last_fail_times[plan_id] = 1.0

    sr._heartbeat_check()

    assert plan_id not in sr._last_fail_times
    assert heartbeat == []


def test_the_cluster_coming_back_re_arms_normally(db, plan, heartbeat):
    """A held plan must not be stuck held once its cluster is configured again."""
    plan_id = plan()
    _connected(DR)
    sr._heartbeat_check()                       # source missing -> held
    assert heartbeat == []

    _connected(PROD, connected=False)           # cluster re-added, site genuinely down
    sr._heartbeat_check()
    assert plan_id in sr._last_fail_times
    sr._heartbeat_check()

    assert heartbeat, 'the plan stayed held after its cluster came back'
