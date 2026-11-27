"""The node shell logs in on the cluster's SSH port.

Both ways in dialled port 22. The SSH server on port+2 got the cluster's ssh_port with the
validate answer and with cluster-creds and never read it; the flask-sock handler on the
main port had the manager at hand and did not read it either. On a cluster whose nodes
listen elsewhere no shell opened. The main port handler is the only node shell now.

paramiko is stopped at the connect, so "dialled" is (host, port) of the login.
"""
import paramiko
import pytest

import pegaprox.api.vms as vms
from test_node_shell_target_1143 import _cluster, _let_go, _shell, _token  # noqa: F401


def _stopped(dialled):
    class _Client(paramiko.SSHClient):
        def connect(self, hostname=None, port=22, **kw):
            dialled.append((hostname, port))
            raise paramiko.AuthenticationException('stopped by the test')
    return _Client


def _dial(api, seed, monkeypatch, port):
    dialled = []
    monkeypatch.setattr(paramiko, 'SSHClient', _stopped(dialled))
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    mgr = _cluster(api)
    mgr.config.ssh_port = port
    _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')
    return dialled


@pytest.mark.parametrize('port,expected', [(2222, 2222), (None, 22), (22, 22)],
                         ids=['2222', 'unset', '22'])
def test_the_main_port_shell_logs_in_on_the_clusters_port(api, seed, monkeypatch, port,
                                                          expected):
    assert _dial(api, seed, monkeypatch, port) == [('10.0.0.12', expected)]


# The save route only stores 1..65535, but a config written before it checked is loaded
# as it is (PegaProxConfig). The shell goes through utils/ssh.node_ssh_port like every other
# SSH path and takes 22 for what is no port.
@pytest.mark.parametrize('port', [0, 'x', 70000, '2222; touch /tmp/x'], ids=['zero', 'word', 'too-big', 'more-than-a-port'])
def test_the_main_port_shell_takes_22_for_anything_that_is_no_port(api, seed, monkeypatch, port):
    assert _dial(api, seed, monkeypatch, port) == [('10.0.0.12', 22)]
