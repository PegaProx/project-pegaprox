"""The node shell logs in on the cluster's SSH port.

Both ways in dialled port 22. The SSH server on port+2 gets the cluster's ssh_port with the
validate answer and with cluster-creds, both put there for it, and never read it. The
flask-sock handler on the main port had the manager at hand and did not read it either. On
a cluster whose nodes listen elsewhere no shell opened.

paramiko is stopped at the connect, so "dialled" is (host, port) of the login.
"""
import asyncio
import json
import types

import paramiko
import pytest

import pegaprox.api.vms as vms
from test_ha_v2_surface import SHELL, _Resp, _ssh_server
from test_node_shell_target_1143 import _Talking, _cluster, _shell, _token


def _stopped(dialled):
    class _Client(paramiko.SSHClient):
        def connect(self, hostname=None, port=22, **kw):
            dialled.append((hostname, port))
            raise paramiko.AuthenticationException('stopped by the test')
    return _Client


def _script(monkeypatch, tmp_path, answers, path):
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    ns, _asked = _ssh_server(answers)
    dialled = []
    fake = types.SimpleNamespace(**vars(paramiko))
    fake.SSHClient = _stopped(dialled)
    ns['paramiko'] = fake
    ws = _Talking(path, json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    return dialled


def _by_token(port):
    ctx = {'host': '192.0.2.1', 'node_ips': {'n1': '192.0.2.11'}}
    if port is not None:
        ctx['ssh_port'] = port
    return {'/api/ws/token/validate': _Resp(200, {'valid': True, 'known_hosts_only': False,
                                                  'cluster_context': ctx})}


def _by_session(port):
    creds = {'host': '192.0.2.1', 'node_ips': {'n1': '192.0.2.11'}}
    if port is not None:
        creds['ssh_port'] = port
    return {'/api/auth/validate': _Resp(200, {'valid': True}),
            '/api/internal/cluster-creds/': _Resp(200, creds)}


WAYS = [(_by_token, f'{SHELL}?token=t'), (_by_session, f'{SHELL}?session=s')]


@pytest.mark.parametrize('answers,path', WAYS, ids=['token', 'session'])
def test_the_ssh_server_logs_in_on_the_clusters_port(monkeypatch, tmp_path, answers, path):
    assert _script(monkeypatch, tmp_path, answers(2222), path) == [('192.0.2.11', 2222)]


@pytest.mark.parametrize('port', [None, 22, 0, 'x', 70000, '2222; touch /tmp/x'],
                         ids=['none', '22', 'zero', 'word', 'too-big', 'more-than-a-port'])
@pytest.mark.parametrize('answers,path', WAYS, ids=['token', 'session'])
def test_the_ssh_server_takes_22_for_anything_that_is_no_port(monkeypatch, tmp_path, answers,
                                                              path, port):
    assert _script(monkeypatch, tmp_path, answers(port), path) == [('192.0.2.11', 22)]


@pytest.mark.parametrize('port,expected', [(2222, 2222), (None, 22), (22, 22)],
                         ids=['2222', 'unset', '22'])
def test_the_main_port_shell_logs_in_on_the_clusters_port(api, seed, monkeypatch, port,
                                                          expected):
    dialled = []
    monkeypatch.setattr(paramiko, 'SSHClient', _stopped(dialled))
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    mgr = _cluster(api)
    mgr.config.ssh_port = port

    _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')

    assert dialled == [('10.0.0.12', expected)]
