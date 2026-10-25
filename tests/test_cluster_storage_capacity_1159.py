"""Guest storage capacity excludes backup/ISO-only datastores (#1159).

These are API fixtures, not a live Proxmox cluster.
"""
from unittest.mock import MagicMock

import pytest

TiB = 1024 ** 4
CID = 'c1'


def _storage(name, content, total, used, node='pve1', plugin='dir'):
    return {'type': 'storage', 'storage': name, 'node': node, 'content': content,
            'plugintype': plugin, 'maxdisk': total * TiB, 'disk': used * TiB}


def _manager(api, resources):
    manager = api.make_fake_manager(CID)
    manager.is_connected = True

    def get(url, **kwargs):
        if url.endswith('/cluster/status'):
            data = [{'type': 'node', 'name': 'pve1', 'online': 1}]
        elif url.endswith('/cluster/resources'):
            data = resources
        else:
            raise AssertionError(f'unexpected read: {url}')
        response = MagicMock(status_code=200)
        response.json.return_value = {'data': data}
        return response

    session = manager._create_session.return_value
    session.get.side_effect = get
    api.set_manager(CID, manager)
    return session


@pytest.mark.parametrize('storages,total,used', [
    ([_storage('local-lvm', 'images,rootdir', 4, 1, plugin='lvmthin'),
      _storage('pbs', 'backup', 80, 40, plugin='pbs')], 4, 1),
    ([_storage('mixed', 'backup,images,iso', 4, 1, plugin='nfs'),
      _storage('containers', 'rootdir', 2, 1),
      _storage('backup', 'backup', 80, 40, plugin='nfs'),
      _storage('iso', 'iso,vztmpl,snippets', 10, 5)], 6, 2),
    ([_storage('pbs', 'backup', 80, 40, plugin='pbs')], 0, 0),
])
def test_capacity_counts_only_storages_that_can_hold_guest_disks(api, seed, storages, total, used):
    session = _manager(api, storages)
    response = api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{CID}/datacenter/status')
    assert response.status_code == 200
    assert response.get_json()['resources']['storage'] == {
        'total': total * TiB, 'used': used * TiB,
        'percent': round(used / total * 100, 1) if total else 0,
    }
    assert session.get.call_count == 2


def test_large_cluster_capacity_needs_no_per_node_or_per_storage_reads(api, seed):
    resources = []
    for node in range(500):
        name = f'pve{node}'
        resources.extend([
            _storage('local-lvm', 'images,rootdir', 4, 1, node=name, plugin='lvmthin'),
            _storage('pbs', 'backup', 80, 40, node=name, plugin='pbs'),
        ])
        resources.extend({'type': 'qemu', 'vmid': node * 4 + vm, 'node': name,
                          'status': 'running'} for vm in range(4))
    session = _manager(api, resources)
    response = api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{CID}/datacenter/status')
    assert response.status_code == 200
    assert response.get_json()['resources']['storage'] == {
        'total': 2000 * TiB, 'used': 500 * TiB, 'percent': 25.0,
    }
    assert response.get_json()['guests']['vms']['total'] == 2000
    assert session.get.call_count == 2
