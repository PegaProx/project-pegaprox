# #686 — the in-band hardware rollup used to go Critical off ANY historical SEL entry, so a
# months-old (already-deasserted) power event pinned the node Critical while every live sensor
# read green. These pin: (1) a resolved SEL event no longer latches the node, (2) an active
# assertion still does AND is surfaced, (3) sensors/chassis surface as the contributor too.

from pegaprox.core.bmc import _health_rollup, _active_sel_events, parse_sel


def _sel(sensor, sev, assertion):
    return {'sensor': sensor, 'severity': sev, 'assertion': assertion, 'description': sensor}


def test_deasserted_critical_sel_does_not_latch_node_critical():
    sensors = [{'name': 'PS1 PG', 'status': 'ok'}, {'name': 'Fan1', 'status': 'ok'}]
    hr = _health_rollup(sensors, [_sel('Power Supply', 'critical', 'deasserted')], {})
    assert hr['status'] == 'ok'
    assert hr['reasons'] == []


def test_active_asserted_critical_sel_drives_critical_and_is_surfaced():
    hr = _health_rollup([{'name': 'PS1 PG', 'status': 'ok'}],
                        [_sel('Power Supply PSU2', 'critical', 'asserted')], {})
    assert hr['status'] == 'critical'
    assert any(r['source'] == 'event' and 'PSU2' in r['label'] for r in hr['reasons'])


def test_newer_deassert_clears_older_assert_for_same_sensor():
    # parse_sel returns newest-first: deassert (newer) then assert (older) -> resolved
    sel = [_sel('Power Supply', 'critical', 'deasserted'), _sel('Power Supply', 'critical', 'asserted')]
    assert _active_sel_events(sel) == []
    assert _health_rollup([], sel, {})['status'] == 'ok'


def test_critical_sensor_is_surfaced():
    hr = _health_rollup([{'name': 'CPU1 Temp', 'status': 'critical'}], [], {})
    assert hr['status'] == 'critical'
    assert any(r['source'] == 'sensor' and r['label'] == 'CPU1 Temp' for r in hr['reasons'])


def test_chassis_intrusion_is_critical_and_surfaced():
    hr = _health_rollup([], [], {'intrusion': 'Active'})
    assert hr['status'] == 'critical'
    assert any(r['source'] == 'chassis' for r in hr['reasons'])


def test_warning_sensor_when_no_critical():
    hr = _health_rollup([{'name': 'Inlet Temp', 'status': 'warning'}], [], {})
    assert hr['status'] == 'warning'
    assert hr['reasons'] and all(r['severity'] == 'warning' for r in hr['reasons'])


def test_all_green_no_events_is_ok():
    hr = _health_rollup([{'name': 'Fan1', 'status': 'ok'}], [], {})
    assert hr['status'] == 'ok' and hr['reasons'] == []


def test_parse_sel_extracts_assertion_state():
    raw = ("12 | 07/14/2026 | 21:30:05 | Power Supply PSU2 | Failure detected | Asserted\n"
           "13 | 07/15/2026 | 08:00:00 | Power Supply PSU2 | Failure detected | Deasserted")
    states = {e['assertion'] for e in parse_sel(raw)}
    assert 'asserted' in states and 'deasserted' in states
