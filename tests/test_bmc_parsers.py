# -*- coding: utf-8 -*-
"""Fixture tests for the in-band BMC/ipmitool parsers (#609).

No hardware needed: `ipmitool` output is deterministic text, so we parse
captured real-world samples and assert the normalized structure + health rollup.
"""
from pegaprox.core import bmc

SDR = """CPU1 Temp        | 01h | ok  |  3.1 | 45 degrees C
CPU2 Temp        | 02h | ok  |  3.2 | 47 degrees C
Inlet Temp       | 04h | ok  |  7.1 | 22 degrees C
Fan1             | 41h | ok  | 29.1 | 4200 RPM
Fan2             | 42h | cr  | 29.2 | 900 RPM
PSU1 Status      | 70h | ok  | 10.1 | Presence detected
Voltage 12V      | 60h | ok  | 60.1 | 12.10 Volts
Pwr Consumption  | 77h | ok  |  7.1 | 210 Watts"""

CHASSIS = """System Power         : on
Power Overload       : false
Main Power Fault     : false
Chassis Intrusion    : inactive"""

POWER = """    Instantaneous power reading:                   210 Watts
    Minimum during sampling period:                120 Watts
    Maximum during sampling period:                340 Watts"""

FRU = """ Product Manufacturer  : Dell Inc.
 Product Name          : PowerEdge R740
 Product Part Number   : 0ABCDE
 Product Serial        : CN7016AB012345"""

SEL = """   1 | 07/10/2026 | 08:00:00 | Fan #0x42 | Lower Critical going low | Asserted
   2 | 07/14/2026 | 21:30:05 | Power Supply PSU2 | Failure detected | Asserted"""


def test_sensors():
    s = {x['name']: x for x in bmc.parse_sensors(SDR)}
    assert s['CPU1 Temp']['kind'] == 'temp' and s['CPU1 Temp']['value'] == 45 and s['CPU1 Temp']['unit'] == '°C'
    assert s['Fan2']['kind'] == 'fan' and s['Fan2']['value'] == 900 and s['Fan2']['status'] == 'critical'
    assert s['Voltage 12V']['kind'] == 'volt' and s['Voltage 12V']['value'] == 12.10
    assert s['Pwr Consumption']['kind'] == 'power' and s['Pwr Consumption']['value'] == 210
    assert s['PSU1 Status']['kind'] == 'discrete' and s['PSU1 Status']['value'] is None and s['PSU1 Status']['status'] == 'ok'


def test_chassis():
    c = bmc.parse_chassis(CHASSIS)
    assert c['power'] == 'on' and c['intrusion'] == 'inactive'


def test_power():
    assert bmc.parse_power(POWER) == 210.0
    assert bmc.parse_power('nothing here') is None


def test_fru():
    f = bmc.parse_fru(FRU)
    assert f['manufacturer'] == 'Dell Inc.' and f['product'] == 'PowerEdge R740'
    assert f['serial'] == 'CN7016AB012345' and f['part'] == '0ABCDE'


def test_sel_newest_first_and_severity():
    ev = bmc.parse_sel(SEL)
    assert ev[0]['id'] == '2' and 'PSU2' in ev[0]['sensor'] and ev[0]['severity'] == 'critical'
    assert ev[1]['id'] == '1' and ev[1]['severity'] == 'critical'
    assert ev[0]['time'] == '07/14/2026 21:30:05'


def _full(sdr=SDR, chassis=CHASSIS, power=POWER, fru=FRU, sel=SEL):
    return (f"__PP_SENSORS__\n{sdr}\n__PP_CHASSIS__\n{chassis}\n"
            f"__PP_POWER__\n{power}\n__PP_FRU__\n{fru}\n__PP_SEL__\n{sel}\n")


def test_parse_inband_full_and_critical_health():
    d = bmc.parse_inband(_full())
    assert d['available'] is True
    assert d['power_w'] == 210.0
    assert d['fru']['serial'] == 'CN7016AB012345'
    assert len(d['sensors']) == 8 and len(d['events']) == 2
    # Fan2 is 'cr' AND a critical PSU failure in the SEL -> node health critical
    assert d['health'] == 'critical'


def test_parse_inband_clean_is_ok():
    clean_sdr = "CPU1 Temp | 01h | ok | 3.1 | 45 degrees C\nFan1 | 41h | ok | 29.1 | 4200 RPM"
    d = bmc.parse_inband(_full(sdr=clean_sdr, sel=""))
    assert d['available'] is True and d['health'] == 'ok'


def test_intrusion_forces_critical():
    d = bmc.parse_inband(_full(chassis="System Power : on\nChassis Intrusion : active", sel=""))
    # even with clean sensors, an active chassis intrusion is critical
    d2 = bmc.parse_inband(_full(sdr="CPU1 Temp | 01h | ok | 3.1 | 45 degrees C",
                                chassis="System Power : on\nChassis Intrusion : active", sel=""))
    assert d2['health'] == 'critical'


def test_unavailable_paths():
    assert bmc.parse_inband('__PP_NO_IPMITOOL__\n')['available'] is False
    assert 'ipmitool' in bmc.parse_inband('__PP_NO_IPMITOOL__\n')['reason']
    assert bmc.parse_inband('__PP_NO_BMC__\n')['available'] is False
    assert bmc.parse_inband('')['available'] is False


def test_read_orchestrator_graceful(monkeypatch):
    # fake manager: no SSH IP -> unavailable, never raises
    class M:
        class config: ssh_user = 'root'
        def _get_node_ip(self, n): return None
    assert bmc.read_node_bmc_inband(M(), 'pve1')['available'] is False

    class M2:
        class config: ssh_user = 'root'
        def _get_node_ip(self, n): return '10.0.0.1'
        def _ssh_run_command_output(self, ip, user, cmd, timeout=15): return _full()
    r = bmc.read_node_bmc_inband(M2(), 'pve1')
    assert r['available'] is True and r['health'] == 'critical' and r['fru']['product'] == 'PowerEdge R740'
