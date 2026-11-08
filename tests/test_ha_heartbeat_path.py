"""The storage heartbeat path goes into the node agent as STORAGE_PATH="<path>", and that
script runs as root on every node. Only the HA settings route checked its shape; the
storages of the cluster (auto-discovery) and the stored settings a start loads put it
into the script as they were, so a storage path with a quote in it ran as a command on
every node. The shape is now checked where the script is filled, and on every way in.

MK Oct 2026
"""
import types
import threading
from unittest.mock import MagicMock

import pytest

from pegaprox.core.manager import PegaProxManager

HOSTILE = [
    '/mnt/pve/nfs"; touch /tmp/pwned; echo "',
    '/mnt/pve/$(id)',
    '/mnt/pve/`id`',
    '/mnt/pve/nfs\nid',
    'mnt/pve/relative',
    '/mnt/pve/a b',
]


def _mgr(**ha_config):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='', host='10.9.0.1',
                                     ha_settings={}, fallback_hosts=[])
    m.current_host = '10.9.0.1'
    m.ha_config = dict(ha_config)
    m.ha_lock = threading.Lock()
    m.logger = MagicMock()
    return m


def _storages(m, listed):
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200, json=lambda: {'data': listed})
    m._create_session = lambda: session
    return m._ha_discover_shared_storages(force_refresh=True)


@pytest.mark.parametrize('path', HOSTILE)
def test_a_storage_of_the_cluster_with_another_path_is_not_used(path):
    m = _mgr()
    found = _storages(m, [{'storage': 'evil', 'type': 'dir', 'shared': 1, 'path': path},
                          {'storage': 'nfs1', 'type': 'nfs', 'shared': 1, 'path': '/mnt/pve/nfs1'}])
    assert [s['path'] for s in found] == ['/mnt/pve/nfs1']


def test_a_plain_path_of_the_cluster_is_used_as_before():
    m = _mgr()
    found = _storages(m, [{'storage': 'cephfs', 'type': 'cephfs', 'shared': 1},
                          {'storage': 'share', 'type': 'dir', 'shared': 1, 'path': '/srv/pve-share_01'}])
    assert [s['path'] for s in found] == ['/mnt/pve/cephfs', '/srv/pve-share_01']


@pytest.mark.parametrize('path', HOSTILE)
def test_the_node_agent_is_not_filled_with_another_path(path, monkeypatch):
    m = _mgr(storage_heartbeat_path=path)
    asked = []
    monkeypatch.setattr(m, '_ha_get_node_ip', lambda node: asked.append(node) or '10.9.0.2', raising=False)
    assert m._ha_install_node_agent('pve1') is False
    # refused before any address was looked up or any SSH went out
    assert asked == []


@pytest.mark.parametrize('path', HOSTILE)
def test_a_stored_path_of_another_shape_is_not_loaded(path):
    m = _mgr()
    m._apply_ha_settings({'storage_heartbeat_path': path, 'storage_heartbeat_enabled': True})
    assert m.ha_config['storage_heartbeat_path'] == ''


def test_a_stored_plain_path_is_loaded_as_before():
    m = _mgr()
    m._apply_ha_settings({'storage_heartbeat_path': '/mnt/pve/nfs1', 'storage_heartbeat_enabled': True})
    assert m.ha_config['storage_heartbeat_path'] == '/mnt/pve/nfs1'


def test_the_route_and_the_manager_check_the_same_shape():
    import inspect
    from pegaprox.api import clusters
    src = inspect.getsource(clusters.update_ha_config)
    assert 'PegaProxManager.HEARTBEAT_PATH_RE.fullmatch' in src
