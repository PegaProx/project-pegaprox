"""Adding a NIC to a container uses PUT.

Proxmox has GET and PUT on a container's config, so the POST add_network sent could not work, the same way add_disk found out earlier.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pegaprox.core.manager import PegaProxManager


@pytest.mark.parametrize('kind,verb', [('lxc', 'put'), ('qemu', 'post')])
def test_each_kind_goes_its_way(kind, verb):
    m = MagicMock(host='h', api_port=8006, is_connected=True)
    sent = []
    m._api_post = lambda url, data=None, **k: sent.append(('post', url, data)) or SimpleNamespace(status_code=200, text='')
    m._api_put = lambda url, data=None, **k: sent.append(('put', url, data)) or SimpleNamespace(status_code=200, text='')
    got = PegaProxManager.add_network(m, 'n1', 100, kind, {'net_id': 'net1', 'bridge': 'vmbr0', 'model': 'virtio', 'name': 'eth1'})
    assert got['success'] is True, got
    assert [s[0] for s in sent] == [verb] and sent[0][1].endswith(f'/{kind}/100/config') and 'net1' in sent[0][2], sent
