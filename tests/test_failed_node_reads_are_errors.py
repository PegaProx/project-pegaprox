"""A node read that Proxmox VE refused, or that never got an answer, is an error.

The routes below answered 200 with [] or {} for both: the node pages then said "no
network interfaces", "no tasks", "no OSDs", "this storage is empty", and nothing told a
refused read from an empty one. Now:

  a) PVE answers a status other than 200: code PVE_READ_FAILED, its status in
     upstream_status and its message in error. A 5xx is a 502, another 4xx keeps its
     status, 401 and 403 are a 502 with UPSTREAM_AUTH (#1142).
  b) the cluster does not answer at all: 503, code PVE_UNREACHABLE, offline true.
  c) the counter-check: the same route with PVE answering 200 hands on the body as before,
     so the error is the failure's and nothing else's.
  d) Ceph: a node without Ceph (PVE 501, or a 500 saying it is not installed or not set
     up) is still {available: false} and empty lists; a Ceph that answered another 500
     (a timeout of the monitors) is an error, it used to read as "no Ceph".

The manager reads run for real on a stand-in manager whose PVE answers are scripted.

MK Nov 2026
"""
import logging
from unittest.mock import MagicMock

import pytest
import requests

CLUSTER = 'cluster_1'
NODE = 'pve1'


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else __import__('json').dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError('not json')
        return self._body


class _FakePve:
    """GET answers by URL suffix: (status, body) or an exception to raise."""

    def __init__(self):
        self.answers = {}
        self.default = (200, {'data': []})
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        for suffix, answer in self.answers.items():
            if url.split('?')[0].endswith(suffix):
                break
        else:
            answer = self.default
        if isinstance(answer, Exception):
            raise answer
        return _Resp(*answer)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


@pytest.fixture
def pve(api):
    from pegaprox.core.manager import PegaProxManager
    fake = _FakePve()
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    m.host, m.api_port = 'pve.test', 8006
    m.logger = logging.getLogger('test.failed_reads')
    m._api_get = lambda url, **kw: fake.get(url, **kw)
    session = MagicMock()
    session.get = fake.get
    m._create_session = lambda: session
    for name in ('get_node_network_config', 'get_node_time', 'get_node_syslog', 'get_node_certificates',
                 'get_node_tasks', 'get_node_subscription', 'get_node_lvm', 'get_node_lvmthin', 'get_node_zfs'):
        setattr(m, name, getattr(PegaProxManager, name).__get__(m, PegaProxManager))
    api.set_manager(CLUSTER, m)
    return fake


# route, the PVE path it reads, a 200 body PVE sends, what the route answers for it
READS = [
    ('network', f'/nodes/{NODE}/network', {'data': [{'iface': 'vmbr0', 'type': 'bridge'}]},
     [{'iface': 'vmbr0', 'type': 'bridge'}]),
    ('time', f'/nodes/{NODE}/time', {'data': {'timezone': 'Europe/Vienna', 'time': 1}},
     {'timezone': 'Europe/Vienna', 'time': 1}),
    ('syslog', f'/nodes/{NODE}/syslog', {'data': [{'n': 1, 't': 'first'}, {'n': 2, 't': 'second'}]},
     ['second', 'first']),
    ('certificates', f'/nodes/{NODE}/certificates/info', {'data': [{'filename': 'pve-ssl.pem'}]},
     [{'filename': 'pve-ssl.pem'}]),
    ('tasks', f'/nodes/{NODE}/tasks', {'data': [{'upid': 'UPID:pve1:1', 'type': 'vzdump'}]},
     [{'upid': 'UPID:pve1:1', 'type': 'vzdump'}]),
    ('subscription', f'/nodes/{NODE}/subscription', {'data': {'status': 'active'}}, {'status': 'active'}),
    ('disks/lvm', f'/nodes/{NODE}/disks/lvm', {'data': [{'vg': 'pve'}]}, [{'vg': 'pve'}]),
    ('disks/lvmthin', f'/nodes/{NODE}/disks/lvmthin', {'data': [{'lv': 'data'}]}, [{'lv': 'data'}]),
    ('disks/zfs', f'/nodes/{NODE}/disks/zfs', {'data': [{'name': 'rpool'}]}, [{'name': 'rpool'}]),
    ('ceph/mon', f'/nodes/{NODE}/ceph/mon', {'data': [{'name': 'pve1'}]}, [{'name': 'pve1'}]),
    ('ceph/mds', f'/nodes/{NODE}/ceph/mds', {'data': [{'name': 'pve1'}]}, [{'name': 'pve1'}]),
    ('ceph/mgr', f'/nodes/{NODE}/ceph/mgr', {'data': [{'name': 'pve1'}]}, [{'name': 'pve1'}]),
    ('ceph/pool', f'/nodes/{NODE}/ceph/pool', {'data': [{'pool_name': 'rbd'}]}, [{'pool_name': 'rbd'}]),
    ('ceph/fs', f'/nodes/{NODE}/ceph/fs', {'data': [{'name': 'cephfs'}]}, [{'name': 'cephfs'}]),
    ('ceph/rules', f'/nodes/{NODE}/ceph/rules', {'data': [{'name': 'replicated_rule'}]}, [{'name': 'replicated_rule'}]),
    ('ceph/log', f'/nodes/{NODE}/ceph/log', {'data': [{'n': 1, 't': 'HEALTH_OK'}]}, [{'n': 1, 't': 'HEALTH_OK'}]),
    ('ceph/osd', f'/nodes/{NODE}/ceph/osd', {'data': {'root': {'type': 'root', 'children': [
        {'type': 'host', 'name': 'pve1', 'children': [{'type': 'osd', 'id': 0, 'name': 'osd.0'}]}]}}},
     [{'type': 'osd', 'id': 0, 'name': 'osd.0', 'host': 'pve1'}]),
    ('hardware/pci', f'/nodes/{NODE}/hardware/pci',
     {'data': [{'id': '0000:00:02.0', 'vendor_name': 'Intel', 'device_name': 'GPU', 'iommugroup': 1}]},
     [{'id': '0000:00:02.0', 'vendor_name': 'Intel', 'device_name': 'GPU', 'iommugroup': 1,
       'display_name': 'Intel GPU', 'passthrough_capable': True}]),
]
IDS = [r[0] for r in READS]


def _url(route):
    return f'/api/clusters/{CLUSTER}/nodes/{NODE}/{route}'


@pytest.mark.parametrize('route,path,ok_body,want', READS, ids=IDS)
def test_a_refusal_of_pve_is_an_error_with_its_reason(admin, pve, route, path, ok_body, want):
    pve.answers[path] = (500, {'data': None, 'message': 'got timeout\n'})
    r = admin.get(_url(route))
    assert r.status_code == 502, (r.status_code, r.get_data(as_text=True))
    body = r.get_json()
    assert body['code'] == 'PVE_READ_FAILED'
    assert body['upstream_status'] == 500
    assert 'got timeout' in body['error']
    # c) the counter-check
    pve.answers[path] = (200, ok_body)
    r = admin.get(_url(route))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == want


@pytest.mark.parametrize('status', [401, 403])
@pytest.mark.parametrize('route,path,ok_body,want', READS, ids=IDS)
def test_refused_credentials_are_upstream_auth(admin, pve, route, path, ok_body, want, status):
    pve.answers[path] = (status, {'data': None, 'message': 'Permission check failed'})
    r = admin.get(_url(route))
    assert r.status_code == 502, (r.status_code, r.get_data(as_text=True))
    assert (r.get_json()['code'], r.get_json()['upstream_status']) == ('UPSTREAM_AUTH', status)


@pytest.mark.parametrize('route,path,ok_body,want', READS, ids=IDS)
def test_another_refusal_of_the_request_keeps_its_status(admin, pve, route, path, ok_body, want):
    # a 4xx other than 401/403 goes out as it came (#1142), with the code and the reason
    pve.answers[path] = (400, {'data': None, 'message': 'value does not match the regex pattern'})
    r = admin.get(_url(route))
    assert r.status_code == 400, (r.status_code, r.get_data(as_text=True))
    body = r.get_json()
    assert (body['code'], body['upstream_status']) == ('PVE_READ_FAILED', 400)
    assert 'regex pattern' in body['error']


@pytest.mark.parametrize('route,path,ok_body,want', READS, ids=IDS)
def test_no_answer_at_all_is_offline(admin, pve, route, path, ok_body, want):
    pve.answers[path] = requests.exceptions.ConnectTimeout('timed out')
    r = admin.get(_url(route))
    assert r.status_code == 503, (r.status_code, r.get_data(as_text=True))
    body = r.get_json()
    assert (body['code'], body['offline']) == ('PVE_UNREACHABLE', True)


# --- d) Ceph -----------------------------------------------------------------------------------

@pytest.mark.parametrize('status,message', [
    (501, 'not implemented'),
    (500, 'binary not installed: /usr/bin/ceph-mon\n'),
    (500, 'pveceph configuration not initialized\n'),
])
def test_a_node_without_ceph_still_says_so(admin, pve, status, message):
    pve.default = (status, {'data': None, 'message': message})
    assert admin.get(_url('ceph/status')).get_json() == {'available': False}
    for lst in ('osd', 'mon', 'pool'):
        r = admin.get(_url(f'ceph/{lst}'))
        assert (r.status_code, r.get_json()) == (200, []), lst


def test_a_ceph_that_did_not_answer_is_not_a_node_without_ceph(admin, pve):
    pve.answers[f'/nodes/{NODE}/ceph/status'] = (500, {'data': None, 'message': 'got timeout\n'})
    r = admin.get(_url('ceph/status'))
    assert r.status_code == 502, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'PVE_READ_FAILED'
    assert 'available' not in r.get_json()
    pve.answers[f'/nodes/{NODE}/ceph/status'] = requests.exceptions.ReadTimeout('slow')
    r = admin.get(_url('ceph/status'))
    assert (r.status_code, r.get_json()['code']) == (503, 'PVE_UNREACHABLE')
    # counter-check: an answer is handed on as it came
    pve.answers[f'/nodes/{NODE}/ceph/status'] = (200, {'data': {'health': {'status': 'HEALTH_OK'}}})
    assert admin.get(_url('ceph/status')).get_json() == {'health': {'status': 'HEALTH_OK'}}


# --- storage content -----------------------------------------------------------------------

def test_a_content_read_pve_refused_is_not_an_empty_storage(admin, pve):
    path = f'/nodes/{NODE}/storage/backup-nfs/content'
    pve.answers[path] = (500, {'data': None, 'message': "storage 'backup-nfs' is not online\n"})
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/backup-nfs/content?node={NODE}')
    assert r.status_code == 502, r.get_data(as_text=True)
    body = r.get_json()
    assert (body['code'], body['upstream_status'], body['node'], body['storage']) == (
        'PVE_READ_FAILED', 500, NODE, 'backup-nfs')
    assert 'not online' in body['error']
    pve.answers[path] = (403, {'message': 'Permission check failed'})
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/backup-nfs/content?node={NODE}')
    assert (r.status_code, r.get_json()['code']) == (502, 'UPSTREAM_AUTH')
    # counter-check
    pve.answers[path] = (200, {'data': [{'volid': 'backup-nfs:iso/a.iso', 'content': 'iso', 'size': 10}]})
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/backup-nfs/content?node={NODE}')
    assert r.status_code == 200
    assert [x['volid'] for x in r.get_json()] == ['backup-nfs:iso/a.iso']


def test_a_content_read_without_a_node_says_the_node_list_failed(admin, pve):
    pve.answers['/api2/json/nodes'] = (500, {'message': 'cluster not ready\n'})
    r = admin.get(f'/api/clusters/{CLUSTER}/datastores/local/content')
    assert r.status_code == 502, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'PVE_READ_FAILED'
    assert 'nodes' in r.get_json()['error']
