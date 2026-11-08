"""Task ids and other request values that end up in a Proxmox VE or PBS API path.

The task routes take the id with a path converter and put it into the URL of the call
as sent. requests folds '.' and '..' segments away before it sends, so an id that
carried one reached another endpoint than the one the route names, past the guest
check, which reads the id's own fields. A task id is now checked for its form before
anything else, and the API sessions of both managers refuse a path with such a
segment, whatever value put it there.
MK Oct 2026
"""
import types
from unittest.mock import MagicMock

import pytest
import requests
from requests.adapters import HTTPAdapter

import pegaprox.globals as ppglobals
from pegaprox.utils.sanitization import refuse_climbing_paths, url_path_climbs, valid_upid

from test_audit_round5_batch13 import _pool_user

GOOD = 'UPID:n1:00001234:0000ABCD:65000000:vzdump:100:root@pam:'
CLIMBING = [GOOD + '/../' + GOOD.replace(':100:', ':101:'),
            GOOD + '/../../qemu/101',
            'x/../../qemu/101',
            GOOD + '/%2e%2e/x']


@pytest.mark.parametrize('url,climbs', [
    ('https://h:8006/api2/json/nodes/n1/tasks/' + GOOD + '/log', False),
    ('https://h:8006/api2/json/nodes/n1/storage/local/content/local:iso/a..b.iso', False),
    ('https://h:8006/api2/json/nodes/n1/tasks?vmid=..', False),
    ('https://h:8006/api2/json/nodes/n1/tasks/x/../../qemu/101', True),
    ('https://h:8006/api2/json/nodes/../cluster/status', True),
    ('https://h:8006/api2/json/nodes/n1/./qemu', True),
    ('https://h:8006/api2/json/nodes/n1/tasks/x/%2E%2E/y', True),
    ('https://h:8006/api2/json/nodes/n1/tasks/x\\..\\y', True),
])
def test_what_counts_as_a_climbing_path(url, climbs):
    assert url_path_climbs(url) is climbs


def test_a_task_id_has_the_form_proxmox_gives_it():
    assert valid_upid(GOOD)
    for bad in CLIMBING + ['', 'UPID:', 'UPID:a b', 'UPID:x?y', 'UPID:x#y', 'qmstart', None, 7]:
        assert not valid_upid(bad), bad


@pytest.mark.parametrize('cluster_type', ['proxmox', 'pve', None, '', 'XCPNG'])
def test_a_cluster_type_nobody_named_gets_the_strict_check(cluster_type):
    from pegaprox.utils.sanitization import task_ref_ok
    assert task_ref_ok(cluster_type, 'n1', GOOD)
    assert not task_ref_ok(cluster_type, 'n1', 'a1b2c3d4')
    assert not task_ref_ok(cluster_type, '..', GOOD)
    # counterproof: XCP-ng and ESXi task references are no UPIDs and still pass
    assert task_ref_ok('xcpng', 'h1', 'a1b2c3d4') and task_ref_ok('esxi', 'h1', 'task-17')
    assert not task_ref_ok('xcpng', 'h1', 'a1/../b')


class _Recorder(HTTPAdapter):
    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append(request.url)
        r = requests.Response()
        r.status_code = 200
        r._content = b'{"data": []}'
        return r


def test_the_session_refuses_a_climbing_path_before_anything_is_sent():
    s = requests.Session()
    rec = _Recorder()
    s.mount('https://', rec)
    refuse_climbing_paths(s)
    with pytest.raises(ValueError):
        s.delete('https://h:8006/api2/json/nodes/n1/tasks/x/../../qemu/101')
    with pytest.raises(ValueError):
        s.get('https://h:8006/api2/json/nodes/n1/tasks/x/%2e%2e/%2e%2e/qemu/101')
    assert rec.sent == []
    # counterproof: unguarded, requests folds it into the guest's own endpoint
    plain = requests.Session()
    plain.mount('https://', rec)
    plain.delete('https://h:8006/api2/json/nodes/n1/tasks/x/../../qemu/101')
    assert rec.sent == ['https://h:8006/api2/json/nodes/n1/qemu/101']
    # and a path as the code names it goes out as it is
    s.get('https://h:8006/api2/json/nodes/n1/tasks/' + GOOD + '/log')
    assert rec.sent[-1].endswith('/tasks/' + GOOD + '/log')


def test_both_managers_build_guarded_sessions():
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.core.pbs import PBSManager
    m = PegaProxManager.__new__(PegaProxManager)
    m._api_token, m._ticket, m._csrf_token, m._ssl_verify = None, None, None, False
    assert getattr(m._create_session(), '_paths_checked', False) is True
    p = PBSManager('p1', {'name': 'pbs', 'host': '10.0.0.5'})
    assert getattr(p._session, '_paths_checked', False) is True


# --- the routes ---------------------------------------------------------------------------

@pytest.fixture
def pve(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_node_task_log.return_value = ['a line']
    m.get_task_status.return_value = {'status': 'stopped', 'exitstatus': 'OK'}
    m.stop_task.return_value = True
    api.set_manager('cluster_1', m)
    return m


@pytest.mark.parametrize('upid', CLIMBING)
@pytest.mark.parametrize('who', ['admin', 'pool'])
def test_a_task_id_that_is_no_task_id_reaches_no_manager(api, seed, pve, upid, who):
    u = seed.user('root', role='admin') if who == 'admin' else _pool_user(seed)
    if who == 'pool':
        seed.db.save_user('mallory', dict(seed.db.get_user('mallory'),
                                          permissions=['node.view', 'vm.stop', 'cluster.view']))
    c = api.as_user(u)
    base = '/api/clusters/cluster_1/nodes/n1/tasks/'
    for method, url in (('get', base + upid + '/log'), ('get', base + upid + '/status'),
                        ('delete', base + upid)):
        r = getattr(c, method)(url)
        assert r.status_code in (400, 404, 405), (method, url, r.status_code)
    assert not pve.get_node_task_log.called
    assert not pve.get_task_status.called
    assert not pve.stop_task.called


def test_a_node_that_is_no_node_name_reaches_no_manager(api, seed, pve):
    c = api.as_user(seed.user('root', role='admin'))
    for node in ('..', '.', 'n1;x'):
        assert c.get(f'/api/clusters/cluster_1/nodes/{node}/tasks/{GOOD}/log').status_code in (400, 404)
    assert not pve.get_node_task_log.called


def test_a_real_task_id_still_works(api, seed, pve):
    c = api.as_user(seed.user('root', role='admin'))
    base = f'/api/clusters/cluster_1/nodes/n1/tasks/{GOOD}'
    r = c.get(base + '/log')
    assert r.status_code == 200 and r.get_json()['log'] == 'a line'
    assert pve.get_node_task_log.call_args[0][:2] == ('n1', GOOD)
    assert c.get(base + '/status').status_code == 200
    assert c.delete(base).status_code == 200
    assert pve.stop_task.call_args[0] == ('n1', GOOD)


def test_the_manager_itself_refuses_a_task_id_that_is_no_task_id():
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.is_connected = True
    m._create_session = MagicMock(side_effect=AssertionError('no request'))
    m._api_delete = MagicMock(side_effect=AssertionError('no request'))
    for upid in CLIMBING:
        assert m.get_node_task_log('n1', upid) == []
        assert m.stop_task('n1', upid) is False
    assert m.stop_task('..', GOOD) is False


@pytest.fixture
def pbs(api):
    from pegaprox.core.pbs import PBSManager
    m = PBSManager('p1', {'name': 'pbs', 'host': '10.0.0.5', 'linked_clusters': ['cluster_1']})
    m.api_get = MagicMock(return_value={'data': {}})
    m.api_delete = MagicMock(return_value={'data': None})
    ppglobals.pbs_managers['p1'] = m
    yield m
    ppglobals.pbs_managers.pop('p1', None)


def test_a_pbs_task_id_that_is_no_task_id_reaches_no_pbs(api, seed, pbs):
    c = api.as_user(seed.user('root', role='admin'))
    for upid in CLIMBING:
        assert c.get(f'/api/pbs/p1/tasks/{upid}').status_code in (400, 404, 405)
        assert c.delete(f'/api/pbs/p1/tasks/{upid}').status_code in (400, 404, 405)
        assert pbs.stop_task(upid) == {'error': 'Invalid task id'}
    assert not pbs.api_get.called and not pbs.api_delete.called
    # counterproof: a real one goes through
    good = 'UPID:pbs:00001234:0000ABCD:00000001:65000000:garbage_collection:store1:root@pam:'
    assert c.get(f'/api/pbs/p1/tasks/{good}').status_code == 200
    assert pbs.api_get.called


def test_an_xcpng_task_reference_is_no_upid_and_still_reads(api, seed):
    m = api.make_fake_manager(cluster_id='cluster_1', cluster_type='xcpng')
    m.is_connected = True
    m.get_node_task_log.return_value = ['Action: start']
    api.set_manager('cluster_1', m)
    c = api.as_user(seed.user('root', role='admin'))
    assert c.get('/api/clusters/cluster_1/nodes/h1/tasks/a1b2c3d4/log').status_code == 200
    assert m.get_node_task_log.call_args[0][:2] == ('h1', 'a1b2c3d4')
    m.get_node_task_log.reset_mock()
    for ref in ('a1b2/../x', 'a1b2/%2e%2e/x'):
        assert c.get(f'/api/clusters/cluster_1/nodes/h1/tasks/{ref}/log').status_code in (400, 404)
    assert not m.get_node_task_log.called
