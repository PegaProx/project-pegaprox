# A cross-hypervisor migration dials the Proxmox node it works on over SSH. When the node's
# network list could not be read (it needs Sys.Audit, which a narrow API token lacks), the
# address of the node PegaProx is connected to stood in for any node: in a cluster of
# several, the migration ran its commands on another node. The manager's own resolver now
# places the node by name, and the connected host stands in only on a one-node cluster.

import types

import pytest

from pegaprox.core import node_creds, xhm


class _Resp:
    def __init__(self, code, data=None):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data or []}


def _mgr(nodes, member_ips=None, network=None):
    m = types.SimpleNamespace(id='c1', host='10.0.0.1', api_port=8006, nodes=nodes)
    m._api_get = lambda url: _Resp(200, network) if network is not None else _Resp(403)
    m.member_node_ip = lambda name: (member_ips or {}).get(name)
    return m


@pytest.fixture(autouse=True)
def _no_address_book(monkeypatch):
    monkeypatch.setattr(node_creds, 'note_address', lambda *a, **k: None)


TWO = {'pve1': {'node': 'pve1'}, 'pve2': {'node': 'pve2'}}


def test_a_node_the_network_read_misses_is_placed_by_the_manager():
    assert xhm._resolve_pve_node_ip(_mgr(TWO, {'pve2': '10.0.0.2'}), 'pve2') == '10.0.0.2'


def test_a_node_nobody_can_place_is_not_dialled_at_another_nodes_address():
    assert xhm._resolve_pve_node_ip(_mgr(TWO), 'pve2') is None


def test_the_connected_host_stands_in_on_a_cluster_of_one_node():
    one = {'pve1': {'node': 'pve1'}}
    assert xhm._resolve_pve_node_ip(_mgr(one), 'pve1') == '10.0.0.1'
    assert xhm._resolve_pve_node_ip(_mgr(one), 'pve9') is None


def test_the_manager_answer_goes_out_without_brackets():
    assert xhm._resolve_pve_node_ip(_mgr(TWO, {'pve2': '[2001:db8::2]'}), 'pve2') == '2001:db8::2'


def test_the_network_read_still_comes_first():
    net = [{'type': 'bridge', 'address': '10.0.0.22'}]
    assert xhm._resolve_pve_node_ip(_mgr(TWO, {'pve2': '10.0.0.2'}, network=net), 'pve2') == '10.0.0.22'
