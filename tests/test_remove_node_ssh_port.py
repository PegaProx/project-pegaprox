"""Removing a node logs in on the cluster's SSH port, on both nodes it touches.

The route runs `pvecm delnode` on a node that stays and then cleans the removed node up,
each over its own SSH login. Both dialled port 22 whatever the cluster had set, so a
cluster whose nodes listen elsewhere could not remove a node at all. Every other node
path (_ssh_connect, _ssh_exec) already takes the cluster's ssh_port.

paramiko is a stub that records each connect, nothing leaves the machine.
"""
import time
import types
from unittest.mock import MagicMock

import pytest

CID = 'c1'
NODE_IPS = {'pve1': '10.0.0.11', 'pve2': '10.0.0.12'}


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


class _Out:
    def __init__(self, payload=b''):
        self._payload = [payload]
        self.channel = types.SimpleNamespace(recv_exit_status=lambda: 0)

    def read(self, *_):
        return self._payload.pop() if self._payload else b''


@pytest.fixture
def remove(api, admin, monkeypatch):
    """Runs the removal of pve2 on a cluster with the given SSH settings and returns the
    (host, port, login) of every connect."""
    import pegaprox.api.vms as vms

    client = MagicMock(name='node-ssh')
    client.exec_command.side_effect = lambda cmd, timeout=None: (
        MagicMock(), _Out(b'pve2\n' if cmd == 'hostname' else b''), _Out())
    shell = MagicMock(name='shell')
    shell.recv_ready.return_value = False
    client.invoke_shell.return_value = shell
    fake = MagicMock(name='paramiko')
    fake.SSHClient.return_value = client
    monkeypatch.setattr(vms, 'get_paramiko', lambda: fake)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda *a, **k: None)
    monkeypatch.setattr(vms, 'secure_ssh_client', lambda pm: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda *a, **k: None)

    class _Time:
        def __getattr__(self, name):
            return getattr(time, name)

        @staticmethod
        def sleep(_s):
            pass
    monkeypatch.setattr(vms, 'time', _Time())

    def run(**ssh):
        mgr = api.make_fake_manager(CID)
        mgr.host, mgr.api_port = '10.0.0.11', 8006
        mgr.config.name, mgr.config.host = 'lab', '10.0.0.11'
        mgr.config.ssh_user, mgr.config.ssh_key = 'root', ''
        mgr.config.excluded_nodes, mgr.config.fallback_hosts = [], []
        for k, v in ssh.items():
            setattr(mgr.config, k, v)
        mgr.nodes_in_maintenance = {}
        nodes = {'data': [{'node': 'pve1', 'status': 'online'},
                          {'node': 'pve2', 'status': 'online'}]}
        mgr._create_session.return_value.get.return_value = types.SimpleNamespace(
            status_code=200, json=lambda: nodes)
        mgr._get_node_ip.side_effect = NODE_IPS.get
        mgr.ssh_password_to_offer.return_value = 'pw'
        api.set_manager(CID, mgr)

        r = admin.delete(f'/api/clusters/{CID}/nodes/pve2/cluster-membership',
                         json={'confirm': True})
        assert r.status_code == 200, r.get_json()
        assert r.get_json().get('success') is True, r.get_json()
        return [(c.args[0], c.kwargs.get('port'), 'pkey' if 'pkey' in c.kwargs else 'password')
                for c in client.connect.call_args_list]
    return run


@pytest.mark.parametrize('key,login', [('', 'password'), ('-----BEGIN KEY-----', 'pkey')],
                         ids=['password', 'stored-key'])
def test_both_nodes_are_dialled_on_the_clusters_ssh_port(remove, key, login):
    dialled = remove(ssh_port=2222, ssh_key=key)

    assert dialled == [('10.0.0.11', 2222, login), ('10.0.0.12', 2222, login)]


@pytest.mark.parametrize('port', [22, None, 0], ids=['22', 'unset', 'zero'])
def test_a_cluster_without_its_own_port_keeps_22(remove, port):
    dialled = remove(ssh_port=port)

    assert dialled == [('10.0.0.11', 22, 'password'), ('10.0.0.12', 22, 'password')]
