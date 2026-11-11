"""Custom scripts and the SMBIOS deploy to all nodes read the node list from PVE's
cluster/status, through the manager's api_port and its HTTP session. An XCP-ng pool has
neither, so a run there ended in a 500 'Could not get cluster nodes' before any node was
asked. Both routes now say plainly that they are for Proxmox VE clusters.

MK Nov 2026
"""
from unittest.mock import MagicMock

import pytest

from pegaprox.utils.auth import hash_password

PW = 'pw-123456'


@pytest.fixture
def root(api, seed):
    salt, h = hash_password(PW)
    seed.db.save_user('root', {'password_salt': salt, 'password_hash': h, 'role': 'admin',
                               'tenant_id': 'default', 'enabled': True, 'permissions': []})
    u = seed.db.get_user('root')
    u['username'] = 'root'
    return api.as_user(u)


def _pool(api, seed):
    from pegaprox.core.xcpng import XcpngManager
    from pegaprox.models.tasks import PegaProxConfig
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted, cluster_type)
                       VALUES ('xcp1', 'xcp1', '10.0.1.1', 'root', 'x', 'xcpng')''')
    mgr = XcpngManager('xcp1', PegaProxConfig({'name': 'xcp1', 'host': '10.0.1.1', 'user': 'root',
                                                'pass': 'pw', 'cluster_type': 'xcpng'}))
    return api.set_manager('xcp1', mgr)


def _pve(api, seed):
    """A Proxmox cluster whose cluster/status lists no node: the route got past the type."""
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    m = api.make_fake_manager('cluster_1')
    m.host, m.api_port = '10.0.0.1', 8006
    m.config.name = 'cluster_1'
    m.config.smbios_autoconfig = {}
    status = MagicMock(status_code=200)
    status.json.return_value = {'data': []}
    m._create_session.return_value.get.return_value = status
    return api.set_manager('cluster_1', m)


def _script(client, cluster_id):
    assert client.get(f'/api/clusters/{cluster_id}/scripts').status_code == 200
    r = client.post(f'/api/clusters/{cluster_id}/scripts', json={'name': 'hello', 'content': 'echo hi'})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['id']


def test_a_script_run_on_an_xcpng_pool_says_it_is_for_proxmox(api, seed, root):
    _pool(api, seed)
    sid = _script(root, 'xcp1')
    r = root.post(f'/api/clusters/xcp1/scripts/{sid}/run', json={'password': PW})
    assert r.status_code == 400, (r.status_code, r.get_data(as_text=True))
    assert 'Proxmox VE' in r.get_json()['error']


def test_a_script_run_on_proxmox_still_reads_the_nodes(api, seed, root):
    m = _pve(api, seed)
    sid = _script(root, 'cluster_1')
    r = root.post(f'/api/clusters/cluster_1/scripts/{sid}/run', json={'password': PW})
    assert r.status_code == 404 and r.get_json()['error'] == 'No target nodes found', r.get_data(as_text=True)
    assert m._create_session.return_value.get.call_args[0][0].endswith('/api2/json/cluster/status')


def test_the_smbios_deploy_to_all_nodes_of_an_xcpng_pool_says_it_is_for_proxmox(api, seed, root):
    _pool(api, seed)
    r = root.post('/api/clusters/xcp1/smbios-autoconfig/deploy-all', json={})
    assert r.status_code == 400, (r.status_code, r.get_data(as_text=True))
    assert 'Proxmox' in r.get_json()['error']


def test_the_smbios_deploy_to_all_nodes_on_proxmox_still_reads_the_nodes(api, seed, root):
    m = _pve(api, seed)
    r = root.post('/api/clusters/cluster_1/smbios-autoconfig/deploy-all', json={})
    assert r.status_code == 404 and r.get_json()['error'] == 'No nodes found in cluster', r.get_data(as_text=True)
    assert m._create_session.return_value.get.call_args[0][0].endswith('/api2/json/cluster/status')
