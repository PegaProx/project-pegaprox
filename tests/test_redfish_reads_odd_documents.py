"""The Redfish reader keeps its "never raises" with documents of an odd shape.

_get handed back whatever the body decoded to, and the reader and the parsers called .get
on it and on every array entry. A list or a bare value for a resource, a link that is no
object, or a null inside Temperatures raised AttributeError out of read_node_bmc_redfish,
and the hardware read and the endpoint test, which call it without a try, answered 500.
Now a document that is no JSON object reads as unavailable, and the reader and the
parsers skip links and entries that are no object and keep the rest.
"""
import json

import pytest

from pegaprox.core import redfish as rf

# the OData id key of a Redfish link ('\u0040' is the at sign)
LINK = '\u0040odata.id'
SYSTEMS = {'Members': [{LINK: '/redfish/v1/Systems/1'}]}
SYSTEM = {'Status': {'Health': 'OK', 'HealthRollup': 'OK'}, 'Manufacturer': 'Dell Inc.', 'PowerState': 'On',
          'LogServices': {LINK: '/redfish/v1/Systems/1/LogServices'}}
CHASSIS = {'Members': [{LINK: '/redfish/v1/Chassis/1'}]}


class _Resp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.headers = {}

    def iter_content(self, n):
        yield json.dumps(self._data).encode()

    def close(self):
        pass


@pytest.fixture
def bmc(monkeypatch):
    routes = {}

    def fake_get(url, **kw):
        for suffix in sorted(routes, key=len, reverse=True):
            if url.endswith(suffix):
                return _Resp(routes[suffix])
        return _Resp({}, status=404)
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)
    return routes


def _read():
    return rf.read_node_bmc_redfish('10.0.0.5', 'ro', 'pw')


@pytest.mark.parametrize('body', [[], [{LINK: '/redfish/v1/Systems/1'}], 'Systems', 5], ids=repr)
def test_a_systems_document_that_is_no_object_reads_unavailable(bmc, body):
    bmc['/redfish/v1/Systems'] = body
    res = _read()
    assert res == {'available': False, 'reason': 'Redfish unreachable: unexpected Redfish document'}, res


@pytest.mark.parametrize('members', [['/redfish/v1/Systems/1'], [None], 'Systems/1', {LINK: '/x'}], ids=repr)
def test_members_that_are_no_link_objects_read_unavailable(bmc, members):
    bmc['/redfish/v1/Systems'] = {'Members': members}
    res = _read()
    assert res['available'] is False, res


def test_a_chassis_or_log_link_that_is_no_string_is_left_out(bmc):
    bmc.update({'/redfish/v1/Systems': SYSTEMS, '/redfish/v1/Systems/1': SYSTEM,
                '/redfish/v1/Chassis': {'Members': [{LINK: 7}]},
                '/redfish/v1/Systems/1/LogServices': {'Members': [{LINK: ['/x']}]}})
    res = _read()
    assert res['available'] is True and res['sensors'] == [] and res['events'] == [], res


def test_null_entries_in_the_sensor_arrays_are_skipped(bmc):
    bmc.update({
        '/redfish/v1/Systems': SYSTEMS, '/redfish/v1/Systems/1': SYSTEM, '/redfish/v1/Chassis': CHASSIS,
        '/redfish/v1/Chassis/1': {},
        '/redfish/v1/Chassis/1/Thermal': {
            'Temperatures': [None, {'Name': 'CPU1 Temp', 'ReadingCelsius': 41, 'Status': 'OK'}, 'x'],
            'Fans': [None, {'Name': 'Fan1', 'Reading': 4200, 'Status': {'Health': 'OK'}}]},
        '/redfish/v1/Chassis/1/Power': {
            'PowerControl': [None, {'PowerConsumedWatts': 180}],
            'Voltages': [7, {'Name': '12V', 'ReadingVolts': 12.0, 'Status': {'Health': 'OK'}}],
            'PowerSupplies': [None, {'Name': 'PSU1', 'PowerOutputWatts': 180, 'Status': None}]},
        '/redfish/v1/Systems/1/LogServices': {'Members': [None, {LINK: '/redfish/v1/Systems/1/LogServices/Sel'}]},
        '/redfish/v1/Systems/1/LogServices/Sel': {'Entries': 'Entries'},
        '/redfish/v1/Systems/1/LogServices/Sel/Entries': {'Members': [
            None, {'Id': '1', 'Severity': 'OK', 'Message': 404}, ['x']]},
    })
    res = _read()
    assert res['available'] is True and res['health'] == 'ok', res
    assert [s['name'] for s in res['sensors']] == ['CPU1 Temp', 'Fan1', '12V', 'PSU1']
    assert res['sensors'][0]['status'] == 'na' and res['sensors'][3]['value'] == 180.0
    assert res['power_w'] == 180.0
    assert res['events'] == [{'id': '1', 'time': '', 'sensor': '', 'description': '404', 'severity': 'info'}]


def test_links_of_the_chassis_that_are_no_objects_fall_back_to_the_usual_paths(bmc):
    bmc.update({
        '/redfish/v1/Systems': SYSTEMS, '/redfish/v1/Systems/1': dict(SYSTEM, LogServices='LogServices'),
        '/redfish/v1/Chassis': CHASSIS,
        '/redfish/v1/Chassis/1': {'Thermal': '/redfish/v1/Chassis/1/Thermal', 'Power': None},
        '/redfish/v1/Chassis/1/Thermal': {'Temperatures': [{'Name': 'Inlet', 'ReadingCelsius': 22}]},
    })
    res = _read()
    assert res['available'] is True and [s['name'] for s in res['sensors']] == ['Inlet'], res


def test_the_parsers_take_a_document_that_is_no_object():
    assert rf.parse_thermal([1]) == [] and rf.parse_power('x') == ([], None) and rf.parse_sel({'a': 1}) == []
    assert rf.parse_system(None)[0] == 'na'


def test_the_endpoint_test_route_answers_unavailable_not_500(api, seed, bmc):
    from pegaprox.core import bmc as bmc_mod
    admin = api.as_user(seed.user('root', role='admin', tenant_id='default'))
    r = admin.post('/api/hardware-monitoring/redfish-consent', json={
        'acknowledge': True, 'ack_version': bmc_mod.REDFISH_CONSENT_VERSION, 'lang': 'en'})
    assert r.status_code == 200, r.get_data(as_text=True)
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    bmc['/redfish/v1/Systems'] = SYSTEMS
    bmc['/redfish/v1/Systems/1'] = SYSTEM
    bmc['/redfish/v1/Chassis'] = CHASSIS
    bmc['/redfish/v1/Chassis/1'] = {}
    bmc['/redfish/v1/Chassis/1/Thermal'] = {'Temperatures': [None]}
    r = admin.post('/api/clusters/cluster_1/nodes/pve1/bmc-endpoint/test',
                   json={'host': '10.0.0.5', 'user': 'ro', 'password': 'pw'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['available'] is True and r.get_json()['health'] == 'ok'
