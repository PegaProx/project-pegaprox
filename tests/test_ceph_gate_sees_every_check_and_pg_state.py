"""The Ceph health gate of a rolling update holds on data at risk.

It compared English sentences with the check codes get_ceph_health_summary hands it, so that
branch never fired, and the summary cut the PG states after three and the checks after five.
A degraded cluster could pass with the gate on, and the next node went down.
"""
import json
from unittest.mock import MagicMock

import pytest

from pegaprox.api.settings import _ceph_gate_unsafe, _ceph_recovery_pending
from pegaprox.core.manager import PegaProxManager


def _summary(status='HEALTH_WARN', checks=(), states=(('active+clean', 100),), up=6, in_=6):
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m._ssh_node_output = lambda node, cmd, timeout=15: json.dumps({
        'health': {'status': status, 'checks': {c: {'severity': 'HEALTH_WARN'} for c in checks}},
        'osdmap': {'num_up_osds': up, 'num_in_osds': in_},
        'pgmap': {'pgs_by_state': [{'state_name': n, 'count': c} for n, c in states]}})
    return m.get_ceph_health_summary(via_node='n1')


@pytest.mark.parametrize('code', ['PG_DEGRADED', 'PG_AVAILABILITY', 'PG_DAMAGED', 'OSD_DOWN', 'OSD_HOST_DOWN',
                                  'OBJECT_UNFOUND', 'MON_DOWN', 'MDS_INSUFFICIENT_STANDBY'])
def test_a_check_with_data_at_risk_holds(code):
    assert code in _ceph_gate_unsafe(_summary(checks=[code]), 'degraded')


@pytest.mark.parametrize('code', ['MON_CLOCK_SKEW', 'OSDMAP_FLAGS', 'RECENT_CRASH', 'OSD_SLOW_OPS', 'OBJECT_MISPLACED',
                                  'PG_NOT_DEEP_SCRUBBED'])
def test_a_benign_check_does_not(code):
    assert _ceph_gate_unsafe(_summary(checks=[code]), 'degraded') is None


def test_the_sixth_check_counts():
    benign = ['MON_CLOCK_SKEW', 'OSDMAP_FLAGS', 'RECENT_CRASH', 'OSD_SLOW_OPS', 'PG_NOT_SCRUBBED']
    summary = _summary(checks=benign + ['PG_DEGRADED'])
    assert 'PG_DEGRADED' in _ceph_gate_unsafe(summary, 'degraded')
    assert _ceph_recovery_pending(summary) is True


def test_the_fourth_pg_state_counts():
    summary = _summary(states=[('active+clean', 900), ('active+clean+scrubbing', 50),
                               ('active+clean+scrubbing+deep', 40), ('active+undersized+degraded', 10)])
    assert 'degraded' in _ceph_gate_unsafe(summary, 'degraded')
    assert _ceph_recovery_pending(summary) is True


def test_data_safe_movement_still_passes_the_gate():
    summary = _summary(states=[('active+clean', 90), ('active+remapped+backfilling', 10)], checks=['OBJECT_MISPLACED'])
    assert _ceph_gate_unsafe(summary, 'degraded') is None


def test_a_healthy_cluster_passes():
    assert _ceph_gate_unsafe(_summary(status='HEALTH_OK'), 'degraded') is None
