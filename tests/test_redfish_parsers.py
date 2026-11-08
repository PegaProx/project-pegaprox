# -*- coding: utf-8 -*-
"""Fixture tests for the out-of-band Redfish reader (#609 phase 3).

No BMC needed: Redfish resources are deterministic JSON, so we parse captured
samples and assert the normalized structure matches the in-band reader's shape,
plus the SSRF host-guard and the in-band -> Redfish combiner.
"""
from pegaprox.core import redfish as rf


SYSTEM = {
    'Status': {'State': 'Enabled', 'Health': 'Critical', 'HealthRollup': 'Critical'},
    'Manufacturer': 'Dell Inc.', 'Model': 'PowerEdge R750',
    'SerialNumber': 'CN7016AB012345', 'PartNumber': '0ABCDE', 'PowerState': 'On',
    'LogServices': {'@odata.id': '/redfish/v1/Systems/1/LogServices'},
}
THERMAL = {
    'Temperatures': [
        {'Name': 'CPU1 Temp', 'ReadingCelsius': 78, 'Status': {'Health': 'OK'}},
        {'Name': 'Inlet Temp', 'ReadingCelsius': 22, 'Status': {'Health': 'OK'}},
    ],
    'Fans': [
        {'Name': 'Fan1', 'Reading': 4200, 'ReadingUnits': 'RPM', 'Status': {'Health': 'OK'}},
        {'Name': 'Fan2', 'Reading': 800, 'ReadingUnits': 'RPM', 'Status': {'Health': 'Critical'}},
    ],
}
POWER = {
    'PowerControl': [{'PowerConsumedWatts': 240}],
    'Voltages': [{'Name': '12V Rail', 'ReadingVolts': 12.1, 'Status': {'Health': 'OK'}}],
    'PowerSupplies': [
        {'Name': 'PSU1', 'Status': {'Health': 'OK', 'State': 'Enabled'}, 'PowerOutputWatts': 240},
        {'Name': 'PSU2', 'Status': {'Health': 'Critical', 'State': 'UnavailableOffline'}},
    ],
}
SEL = [
    {'Id': '1', 'Created': '2026-07-16T08:00:00Z', 'Severity': 'OK', 'Message': 'System boot', 'SensorType': 'System'},
    {'Id': '2', 'Created': '2026-07-16T09:30:00Z', 'Severity': 'Critical', 'Message': 'PSU2 failure detected', 'SensorType': 'Power Supply'},
]


def test_health_mapping():
    assert rf._health('OK') == 'ok'
    assert rf._health('Warning') == 'warning'
    assert rf._health('Critical') == 'critical'
    assert rf._health('') == 'na' and rf._health(None) == 'na'


def test_parse_thermal():
    s = {x['name']: x for x in rf.parse_thermal(THERMAL)}
    assert s['CPU1 Temp']['kind'] == 'temp' and s['CPU1 Temp']['value'] == 78 and s['CPU1 Temp']['unit'] == '°C'
    assert s['Fan2']['kind'] == 'fan' and s['Fan2']['value'] == 800 and s['Fan2']['status'] == 'critical'
    assert s['Fan1']['status'] == 'ok'


def test_parse_power():
    sensors, watts = rf.parse_power(POWER)
    assert watts == 240.0
    byname = {x['name']: x for x in sensors}
    assert byname['12V Rail']['kind'] == 'volt' and byname['12V Rail']['value'] == 12.1
    assert byname['PSU2']['status'] == 'critical'
    assert byname['PSU1']['kind'] == 'power' and byname['PSU1']['value'] == 240


def test_parse_system():
    health, fru, chassis = rf.parse_system(SYSTEM)
    assert health == 'critical'
    assert fru['manufacturer'] == 'Dell Inc.' and fru['product'] == 'PowerEdge R750'
    assert fru['serial'] == 'CN7016AB012345' and fru['part'] == '0ABCDE'
    assert chassis['power'] == 'on'


def test_parse_sel_newest_first():
    ev = rf.parse_sel(SEL)
    assert ev[0]['id'] == '2' and ev[0]['severity'] == 'critical' and 'PSU2' in ev[0]['description']
    assert ev[1]['id'] == '1' and ev[1]['severity'] == 'info'


def test_parse_redfish_full_and_critical():
    d = rf.parse_redfish(SYSTEM, THERMAL, POWER, SEL)
    assert d['available'] is True and d['source'] == 'redfish'
    assert d['health'] == 'critical'
    assert d['power_w'] == 240.0
    assert d['fru']['serial'] == 'CN7016AB012345'
    assert len(d['events']) == 2
    # Fan2 critical + PSU2 critical + system Critical + SEL critical
    assert any(s['status'] == 'critical' for s in d['sensors'])


def test_parse_redfish_clean_is_ok():
    sys_ok = dict(SYSTEM, Status={'Health': 'OK', 'HealthRollup': 'OK'})
    thermal_ok = {'Temperatures': [{'Name': 'CPU', 'ReadingCelsius': 45, 'Status': {'Health': 'OK'}}], 'Fans': []}
    d = rf.parse_redfish(sys_ok, thermal_ok, {'PowerControl': [{'PowerConsumedWatts': 100}]}, [])
    assert d['available'] is True and d['health'] == 'ok'


def test_parse_redfish_empty_unavailable():
    assert rf.parse_redfish({}, {}, {}, [])['available'] is False


def test_host_guard_blocks_metadata_allows_private():
    # cloud-metadata always blocked even though allow_private=True for BMCs
    base, why = rf._validate_host('169.254.169.254')
    assert base is None
    # a private mgmt-LAN IP is allowed (BMCs live there); bare host gets https:// prefixed
    base2, why2 = rf._validate_host('10.20.30.40')
    assert base2 == 'https://10.20.30.40', (base2, why2)
    # an explicit http scheme is preserved
    base3, _ = rf._validate_host('http://10.20.30.40')
    assert base3 == 'http://10.20.30.40'
    # an unresolvable hostname fails CLOSED (DNS-rebind defense; require_resolution)
    assert rf._validate_host('nope.invalid.example')[0] is None
    # empty rejected
    assert rf._validate_host('')[0] is None


def test_read_node_hardware_prefers_inband(monkeypatch):
    # in-band available -> used, tagged source=inband, redfish never called
    monkeypatch.setattr('pegaprox.core.bmc.read_node_bmc_inband',
                        lambda mgr, node, **k: {'available': True, 'health': 'ok', 'sensors': [], 'events': [], 'chassis': {}})
    called = {'rf': False}
    monkeypatch.setattr('pegaprox.core.redfish.read_node_bmc_redfish',
                        lambda *a, **k: called.__setitem__('rf', True) or {'available': True})
    r = rf.read_node_hardware(object(), 'cluster_1', 'pve1', inband_ok=True, redfish_ok=True)
    assert r['available'] is True and r['source'] == 'inband'
    assert called['rf'] is False


def test_read_node_hardware_falls_back_to_redfish(monkeypatch):
    # in-band unavailable + endpoint configured -> redfish used
    monkeypatch.setattr('pegaprox.core.bmc.read_node_bmc_inband',
                        lambda mgr, node, **k: {'available': False, 'reason': 'no ipmitool'})
    monkeypatch.setattr('pegaprox.core.redfish.read_node_bmc_redfish',
                        lambda *a, **k: {'available': True, 'source': 'redfish', 'health': 'warning', 'sensors': [], 'events': [], 'chassis': {}})

    class _DB:
        def get_bmc_endpoint(self, cid, node):
            return {'enabled': True, 'host': '10.0.0.9', 'user': 'ro', 'password': 'x', 'verify_ssl': False}
    monkeypatch.setattr('pegaprox.core.db.get_db', lambda: _DB())

    r = rf.read_node_hardware(object(), 'cluster_1', 'pve1', inband_ok=True, redfish_ok=True)
    assert r['available'] is True and r['source'] == 'redfish' and r['health'] == 'warning'


def test_read_node_hardware_no_source_available(monkeypatch):
    monkeypatch.setattr('pegaprox.core.bmc.read_node_bmc_inband',
                        lambda mgr, node, **k: {'available': False, 'reason': 'no ipmitool'})

    class _DB:
        def get_bmc_endpoint(self, cid, node):
            return None
    monkeypatch.setattr('pegaprox.core.db.get_db', lambda: _DB())
    r = rf.read_node_hardware(object(), 'cluster_1', 'pve1', inband_ok=True, redfish_ok=True)
    assert r['available'] is False


# --- security regressions (#609 phase 3 review) -------------------------------

class _FakeResp:
    def __init__(self, data, status=200, headers=None):
        self._data = data
        self.status_code = status
        self.headers = headers or {}
    def iter_content(self, n):
        yield __import__('json').dumps(self._data).encode()
    def close(self):
        pass


def test_ssrf_hostile_odata_id_never_leaves_origin(monkeypatch):
    # A hostile BMC returns a Members[0].@odata.id that userinfo-splices the metadata
    # IP ('@169.254.169.254/...'). The reader must pin every hop to the validated
    # base host, so requests.get is NEVER called with the attacker host.
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        if url.endswith('/redfish/v1/Systems'):
            return _FakeResp({'Members': [{'@odata.id': '@169.254.169.254/latest/meta-data/'}]})
        return _FakeResp({})
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)

    res = rf.read_node_bmc_redfish('10.0.0.5', 'u', 'p', verify_ssl=False)
    assert all('169.254.169.254' not in u for u in seen), seen   # never hit the metadata host
    assert res['available'] is False                              # hostile ref rejected -> no system doc


def test_ssrf_absolute_and_protocol_relative_odata_id_rejected(monkeypatch):
    for hostile in ('https://evil.example/x', '//evil.example/x'):
        seen = []

        def fake_get(url, _h=hostile, **kw):
            seen.append(url)
            if url.endswith('/redfish/v1/Systems'):
                return _FakeResp({'Members': [{'@odata.id': _h}]})
            return _FakeResp({})
        monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)
        res = rf.read_node_bmc_redfish('10.0.0.5', 'u', 'p')
        assert all('evil.example' not in u for u in seen), (hostile, seen)
        assert res['available'] is False


def test_redfish_body_size_cap(monkeypatch):
    # a BMC advertising a huge Content-Length is refused before buffering
    def fake_get(url, **kw):
        if url.endswith('/redfish/v1/Systems'):
            return _FakeResp({'Members': []}, headers={'Content-Length': str(50 * 1024 * 1024)})
        return _FakeResp({})
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)
    res = rf.read_node_bmc_redfish('10.0.0.5', 'u', 'p')
    assert res['available'] is False
