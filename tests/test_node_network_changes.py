"""The pending network changes of a node: what waits in interfaces.new until Apply.

PVE's GET nodes/<node>/network puts the unified diff of the running file against the pending
one next to the list, as the attribute 'changes', and leaves it out when nothing waits. The
list read of PegaProx hands on only the list. GET .../network/changes hands on the diff, under
the same access as the list read, says when PVE did not answer instead of answering "nothing
waits", and writes nothing.

MK Nov 2026
"""
import json
import types

import pytest
import requests

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/nodes/pve1/network/changes'
LIST = f'/api/clusters/{CID}/nodes/pve1/network'

DIFF = ('--- /etc/network/interfaces\t2026-10-30 09:00:00\n'
        '+++ /etc/network/interfaces.new\t2026-11-01 10:00:00\n'
        '@@ -10,3 +10,3 @@\n'
        ' iface vmbr0 inet static\n'
        '-\taddress 10.0.0.11/24\n'
        '+\taddress 10.0.0.12/24\n')
ROWS = [{'iface': 'vmbr0', 'type': 'bridge', 'active': 1, 'cidr': '10.0.0.12/24'}]


class _Resp:
    def __init__(self, status, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Upstream:
    def __init__(self, answer):
        self.answer, self.urls = answer, []

    def get(self, url, **kw):
        self.urls.append(url)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _manager(api, answer=None, cluster_type='proxmox', connected=True):
    m = api.make_fake_manager(CID, cluster_type=cluster_type)
    m.config = types.SimpleNamespace(name=CID)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, connected
    up = _Upstream(answer if answer is not None else _Resp(200, {'data': ROWS, 'changes': DIFF}))
    m._api_get = up.get
    m._create_session.return_value = up
    m.get_node_network_config.return_value = ROWS
    up.manager = m
    api.set_manager(CID, m)
    return up


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def test_the_diff_pve_sends_is_handed_on(api, admin):
    up = _manager(api)
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    assert r.get_json() == {'changes': DIFF}
    assert up.urls == ['https://192.0.2.10:8006/api2/json/nodes/pve1/network']


def test_nothing_waiting_is_an_empty_text(api, admin):
    # PVE leaves the attribute out when interfaces.new is missing or the same
    _manager(api, _Resp(200, {'data': ROWS}))
    r = admin.get(URL)
    assert r.status_code == 200 and r.get_json() == {'changes': ''}


def test_the_list_read_keeps_its_answer(api, admin):
    _manager(api)
    r = admin.get(LIST)
    assert r.status_code == 200 and r.get_json() == ROWS


@pytest.mark.parametrize('status', [500, 596, 404])
def test_a_failed_read_is_said_not_given_as_nothing_waiting(api, admin, status):
    _manager(api, _Resp(status, None, json.dumps({'data': None, 'message': 'node pve1 not found'})))
    r = admin.get(URL)
    assert r.status_code == 502, r.data
    body = r.get_json()
    assert 'changes' not in body and body['upstream_status'] == status and body['error']


def test_an_answer_that_is_not_json_is_a_failed_read(api, admin):
    _manager(api, _Resp(200, ValueError('no json'), '<html>proxy error</html>'))
    r = admin.get(URL)
    assert r.status_code == 502 and 'changes' not in r.get_json()


# a body or an attribute of a shape the route does not know is a failed read too, not "nothing
# waits": a list or null as the body, a number or an object as the diff
@pytest.mark.parametrize('body', [[], [{'changes': DIFF}], None, 'changes', {'data': ROWS, 'changes': 5},
                                  {'data': ROWS, 'changes': {'text': DIFF}}, {'data': ROWS, 'changes': [DIFF]}])
def test_an_answer_of_another_shape_is_a_failed_read(api, admin, body):
    _manager(api, _Resp(200, body))
    r = admin.get(URL)
    assert r.status_code == 502, (body, r.status_code, r.data)
    got = r.get_json()
    assert 'changes' not in got and got['error'] and got['upstream_status'] == 200


def test_a_null_attribute_is_nothing_waiting(api, admin):
    _manager(api, _Resp(200, {'data': ROWS, 'changes': None}))
    r = admin.get(URL)
    assert r.status_code == 200 and r.get_json() == {'changes': ''}


@pytest.mark.parametrize('status', [401, 403])
def test_refused_credentials_name_the_cluster_side(api, admin, status):
    _manager(api, _Resp(status, None, json.dumps({'data': None, 'message': 'Permission check failed'})))
    r = admin.get(URL)
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH', r.data
    assert 'changes' not in r.get_json()


@pytest.mark.parametrize('fault', [requests.exceptions.ConnectionError('down'), requests.exceptions.Timeout('slow')])
def test_an_unreachable_cluster_is_a_503(api, admin, fault):
    _manager(api, fault)
    r = admin.get(URL)
    assert r.status_code == 503 and r.get_json()['offline'] is True and 'changes' not in r.get_json()


def test_a_cluster_that_does_not_connect_is_a_503(api, admin):
    up = _manager(api, connected=False)
    up.manager.connect_to_proxmox.return_value = False
    r = admin.get(URL)
    assert r.status_code == 503 and up.urls == []


@pytest.mark.parametrize('node', ['pve1;id', '-pve', 'p' * 70, '..'])
def test_a_bad_node_name_reaches_no_cluster(api, admin, node):
    up = _manager(api)
    r = admin.get(f'/api/clusters/{CID}/nodes/{node}/network/changes')
    assert r.status_code in (400, 404), (node, r.status_code)
    assert up.urls == []


def test_an_xcpng_pool_has_no_pending_diff(api, admin):
    up = _manager(api, cluster_type='xcpng')
    r = admin.get(URL)
    assert r.status_code == 501 and r.get_json()['code'] == 'NOT_SUPPORTED' and up.urls == []


def test_it_only_reads(api, admin):
    up = _manager(api)
    admin.get(URL)
    m = up.manager
    for write in ('apply_node_network', 'revert_node_network', 'update_node_network', 'create_node_network',
                  'delete_node_network', '_api_put', '_api_post', '_api_delete'):
        assert not getattr(m, write).called, write


def _identities(api, seed):
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    seed.tenant('t_confined', [])
    seed.vm_acl(CID, 100, ['portal'], permissions=['vm.view'])
    return {
        'admin': api.as_user(seed.user('root', role='admin')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'no_node_view': api.as_user(seed.user('plain', role='user', permissions=[])),
        'acl_only': api.as_user(seed.user('portal', role='user', tenant_id='t_confined')),
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}})),
        'other_tenant': api.as_user(seed.user('ac', role='user', tenant_id='acme', permissions=['node.view'])),
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }


def test_the_same_callers_as_the_list_read(api, seed):
    who = _identities(api, seed)
    up = _manager(api)
    seen = {}
    for name, client in who.items():
        before = len(up.urls)
        listed = client.get(LIST).status_code
        changes = client.get(URL).status_code
        seen[name] = listed
        assert changes == listed, (name, listed, changes)
        if changes != 200:
            assert len(up.urls) == before, name
    # the comparison means something only when both outcomes occur
    assert 200 in seen.values() and any(s in (401, 403) for s in seen.values()), seen
