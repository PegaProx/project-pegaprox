# #686 — the in-band hardware rollup used to go Critical off ANY historical SEL entry, so a
# months-old (already-deasserted) power event pinned the node Critical while every live sensor
# read green.
# #714 (NS) — even the "currently-active assertion" carve-out wasn't enough on HP iLO 4/ProLiant
# Gen9: the recovery logs one 'Redundancy Lost — Deasserted' on the Power-Unit sensor while the
# per-PSU 'failure — Asserted' sits on a different sensor name and never gets its own deassert, so
# pairing can't clear it and the node stayed Critical over a green live iLO. The SEL is now history
# only — live sensors + chassis drive the badge (matching the Redfish rollup); SEL entries are
# tagged active/historical for the event log.

from pegaprox.core.bmc import _health_rollup, _active_sel_events, parse_sel, parse_inband


def _sel(sensor, sev, assertion):
    return {'sensor': sensor, 'severity': sev, 'assertion': assertion, 'description': sensor}


def test_deasserted_critical_sel_does_not_latch_node_critical():
    sensors = [{'name': 'PS1 PG', 'status': 'ok'}, {'name': 'Fan1', 'status': 'ok'}]
    hr = _health_rollup(sensors, [_sel('Power Supply', 'critical', 'deasserted')], {})
    assert hr['status'] == 'ok'
    assert hr['reasons'] == []


def test_active_asserted_sel_no_longer_drives_badge_when_sensors_green():
    # #714 — an unpaired active PSU-failure assertion must NOT latch the node while the live
    # sensor for that supply reads OK; the SEL is history, not current state.
    hr = _health_rollup([{'name': 'PS1 PG', 'status': 'ok'}],
                        [_sel('Power Supply PSU2', 'critical', 'asserted')], {})
    assert hr['status'] == 'ok'
    assert all(r['source'] != 'event' for r in hr['reasons'])


def test_714_ilo4_cross_sensor_recovery_reads_ok():
    # the exact iLO 4 shape: per-PSU failure asserted on one sensor, redundancy restored logged as
    # a deassert on a DIFFERENT sensor (so pairing can't clear the assert). Live sensors all OK ->
    # node must read OK, not Critical.
    sel = [_sel('Power Unit', 'critical', 'deasserted'),        # 'Redundancy Lost — Deasserted'
           _sel('Power Supply 2', 'critical', 'asserted')]      # older per-PSU failure, never paired
    sensors = [{'name': 'PS1 Status', 'status': 'ok'}, {'name': 'PS2 Status', 'status': 'ok'},
               {'name': 'Fan Redundancy', 'status': 'ok'}]
    assert _health_rollup(sensors, sel, {})['status'] == 'ok'


def test_live_sensor_fault_still_drives_critical():
    # guard: dropping SEL from the badge must NOT blind us to a genuine live fault.
    hr = _health_rollup([{'name': 'PS2 Status', 'status': 'critical'}],
                        [_sel('Power Supply 2', 'critical', 'asserted')], {})
    assert hr['status'] == 'critical'
    assert any(r['source'] == 'sensor' and 'PS2' in r['label'] for r in hr['reasons'])


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


def test_parse_inband_tags_active_events_but_badge_stays_ok():
    # #714 end-to-end: the exact iLO 4 cross-sensor shape via parse_inband. Badge reads OK (SEL is
    # history), and the unpaired PSU-failure assert is tagged active for the event-log UI.
    raw = ("__PP_SEL__\n"
           "12 | 07/14/2026 | 21:30:05 | Power Supply 2 | Failure detected | Asserted\n"
           "13 | 07/15/2026 | 08:00:00 | Power Unit | Redundancy Lost | Deasserted\n")
    res = parse_inband(raw)
    assert res['available'] is True
    assert res['health'] == 'ok'
    active = [e for e in res['events'] if e.get('active')]
    assert any('Power Supply' in (e.get('sensor') or '') for e in active)
    assert all(e.get('assertion') != 'deasserted' for e in active)
