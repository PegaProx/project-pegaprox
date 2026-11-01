"""The pending list of a VM: what of its config waits for the next start, as PVE reports it.

GET /nodes/<node>/qemu/<vmid>/pending answers every key of the config with its running value
and, where a change waits, 'pending' or 'delete' (2 = forced). The route hands on only the keys
that wait, under the same access as reading the config (vm.view on that VM), masks the
cloud-init password whatever the PVE version sends, and says when PVE did not answer instead
of returning an empty list. It writes nothing.

MK Nov 2026
"""
import json
import types

import pytest
import requests

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/vms/pve1/qemu/100/pending'

PENDING = [
    {'key': 'name', 'value': 'web-01'},
    {'key': 'cores', 'value': 2, 'pending': 4},
    {'key': 'balloon', 'value': 1024, 'delete': 1},
    {'key': 'hostpci0', 'value': '0000:01:00.0', 'delete': 2},
    {'key': 'vga', 'pending': 'virtio'},
    {'key': 'cipassword', 'value': '$5$plain-hash', 'pending': '$5$other-hash'},
    {'key': 'digest', 'value': 'abc123'},
    {'value': 'no key'},
]


class _Resp:
    def __init__(self, status, data=None, message=None):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data, 'message': message} if message else {'data': data})

    def json(self):
        return {'data': self._data}


class _Session:
    def __init__(self, answer):
        self.answer, self.urls = answer, []

    def get(self, url, timeout=None):
        self.urls.append(url)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _manager(api, answer=None, cluster_type='proxmox'):
    m = api.make_fake_manager(CID, cluster_type=cluster_type)
    m.config = types.SimpleNamespace(name=CID)
    m.host, m.api_port, m.is_connected = '192.0.2.10', 8006, True
    session = _Session(answer if answer is not None else _Resp(200, PENDING))
    m._create_session = lambda: session
    session.manager = m
    api.set_manager(CID, m)
    return session


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def test_only_the_keys_that_wait_are_handed_on(api, admin):
    session = _manager(api)
    r = admin.get(URL)
    assert r.status_code == 200, r.data
    assert session.urls == ['https://192.0.2.10:8006/api2/json/nodes/pve1/qemu/100/pending']
    rows = {row['key']: row for row in r.get_json()['pending']}
    assert set(rows) == {'cores', 'balloon', 'hostpci0', 'vga', 'cipassword'}
    assert rows['cores'] == {'key': 'cores', 'value': 2, 'pending': 4}
    assert rows['balloon'] == {'key': 'balloon', 'value': 1024, 'delete': 1}
    assert rows['hostpci0']['delete'] == 2
    # a key PVE adds with no running value yet
    assert rows['vga'] == {'key': 'vga', 'pending': 'virtio'}


def test_the_cloud_init_password_is_masked(api, admin):
    _manager(api)
    rows = {row['key']: row for row in admin.get(URL).get_json()['pending']}
    assert rows['cipassword'] == {'key': 'cipassword', 'value': '**********', 'pending': '**********'}
    assert 'hash' not in json.dumps(rows)


def test_nothing_waiting_is_an_empty_list(api, admin):
    _manager(api, _Resp(200, [{'key': 'name', 'value': 'web-01'}, {'key': 'memory', 'value': 2048, 'delete': 0}]))
    r = admin.get(URL)
    assert r.status_code == 200 and r.get_json() == {'pending': []}


@pytest.mark.parametrize('status,code', [(500, 502), (596, 502), (404, 502)])
def test_a_failed_read_is_said_not_given_as_nothing_waiting(api, admin, status, code):
    _manager(api, _Resp(status, None, 'VM 100 is locked'))
    r = admin.get(URL)
    assert r.status_code == code, r.data
    body = r.get_json()
    assert 'pending' not in body and body['upstream_status'] == status


def test_refused_credentials_name_the_cluster_side(api, admin):
    _manager(api, _Resp(403, None, 'Permission check failed'))
    r = admin.get(URL)
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH', r.data


def test_an_unreachable_cluster_is_a_503(api, admin):
    _manager(api, requests.exceptions.ConnectionError('down'))
    r = admin.get(URL)
    assert r.status_code == 503 and r.get_json()['offline'] is True


@pytest.mark.parametrize('node', ['pve1;id', '-pve', 'p' * 70, '..'])
def test_a_bad_node_name_reaches_no_cluster(api, admin, node):
    session = _manager(api)
    r = admin.get(f'/api/clusters/{CID}/vms/{node}/qemu/100/pending')
    assert r.status_code in (400, 404), (node, r.status_code)
    assert session.urls == []


def test_an_xcpng_pool_has_no_pending_list(api, admin):
    session = _manager(api, cluster_type='xcpng')
    r = admin.get(URL)
    assert r.status_code == 400 and session.urls == []


def test_it_only_reads(api, admin):
    session = _manager(api)
    # a POST lands on the guest action route, which knows no action "pending"
    for method, status in (('post', 400), ('put', 405), ('delete', 405)):
        assert getattr(admin, method)(URL, json={}).status_code == status, method
    assert session.urls == []
    assert not session.manager.vm_action.called


def _identities(api, seed):
    seed.tenant('globex', ['cluster_globex'])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    # reach the cluster through a VM ACL only, on this VM or on another one
    seed.tenant('t_confined', [])
    seed.vm_acl(CID, 100, ['portal'], permissions=['vm.view'])
    seed.vm_acl(CID, 200, ['portal2'], permissions=['vm.view'])
    return {
        'acl_this_vm': api.as_user(seed.user('portal', role='user', tenant_id='t_confined')),
        'acl_other_vm': api.as_user(seed.user('portal2', role='user', tenant_id='t_confined')),
        'admin': api.as_user(seed.user('root', role='admin')),
        'viewer': api.as_user(seed.user('watcher', role='viewer')),
        'confined_admin': api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                                tenant_permissions={'globex': {'role': 'user'}})),
        'other_tenant': api.as_user(seed.user('ac', role='user', tenant_id='acme',
                                              permissions=['vm.config', 'vm.view'])),
        'owning_tenant': api.as_user(seed.user('op', role='user', tenant_id='ops')),
    }


def test_the_same_callers_as_the_config_read(api, seed):
    who = _identities(api, seed)
    session = _manager(api)
    session.manager.get_vm_config.return_value = {'success': True, 'config': {'raw': {'name': 'web-01'}}}
    config = f'/api/clusters/{CID}/vms/pve1/qemu/100/config'
    expect = {'admin': 200, 'viewer': 200, 'confined_admin': 403, 'other_tenant': 403, 'owning_tenant': 200,
              'acl_this_vm': 200, 'acl_other_vm': 403}
    for name, status in expect.items():
        before = len(session.urls)
        assert who[name].get(URL).status_code == status, name
        assert who[name].get(config).status_code == status, name
        if status != 200:
            assert len(session.urls) == before, name
