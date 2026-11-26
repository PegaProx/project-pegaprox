# The HA maintenance flag of a node went out over SSH only (ha-manager crm-command
# node-maintenance), with sudo for a non-root login and not at all for a cluster that has no
# SSH. pve-manager 9.2 has PUT /nodes/{node}/maintenance, which runs that same command on the
# PVE side. PegaProx asks the API first; SSH stays for nodes without the endpoint (501), a
# login without Sys.Modify on / (403), a refusal and a request that does not get through.

import types

import pytest
import requests

from pegaprox.models.tasks import PegaProxConfig


def _manager(api_answer, ssh_ok=True):
    """A bare manager with the API PUT and the SSH steps recorded."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = PegaProxConfig({'name': 'c', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m.id = 'c1'
    m.current_host = None
    quiet = lambda *a, **k: None
    m.logger = types.SimpleNamespace(info=quiet, debug=quiet, warning=quiet, error=quiet,
                                     critical=quiet)
    m.puts, m.ssh = [], []

    def put(url, **kw):
        m.puts.append((url, kw.get('data')))
        if isinstance(api_answer, Exception):
            raise api_answer
        return types.SimpleNamespace(status_code=api_answer, reason='as PVE answers')

    def ssh(ip, user, cmd, *a, **kw):
        m.ssh.append(cmd)
        return ssh_ok
    m._api_put = put
    m._ssh_run_command = m._ssh_run_command_with_key = m._ssh_run_command_with_password = ssh
    m.ssh_password_to_offer = lambda ip: None
    m._get_node_ip = lambda node: '10.0.0.7'
    m.get_node_status = lambda: {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    return m


def _task():
    return types.SimpleNamespace(native_ha=False)


URL = 'https://10.0.0.1:8006/api2/json/nodes/pve1/maintenance'


def test_a_node_with_the_endpoint_gets_the_flag_over_the_api():
    m, task = _manager(200), _task()
    assert m._try_native_ha_maintenance('pve1', task) is True
    assert task.native_ha is True
    assert m.puts == [(URL, {'maintenance-mode': 'enable'})]
    assert m.ssh == []


def test_the_flag_comes_off_over_the_api_too():
    m = _manager(200)
    assert m._try_disable_native_ha_maintenance('pve1') is True
    assert m.puts == [(URL, {'maintenance-mode': 'disable'})]
    assert m.ssh == []


FALLBACKS = {
    'node without the endpoint': 501,
    'login without Sys.Modify': 403,
    'ha-manager refused it': 500,
    'no answer': requests.exceptions.ConnectionError('refused'),
}


@pytest.mark.parametrize('why', sorted(FALLBACKS))
def test_ssh_sets_the_flag_when_the_api_does_not(why):
    m, task = _manager(FALLBACKS[why]), _task()
    assert m._try_native_ha_maintenance('pve1', task) is True
    assert task.native_ha is True
    assert len(m.puts) == 1
    assert m.ssh and all(c == 'ha-manager crm-command node-maintenance enable pve1' for c in m.ssh)


@pytest.mark.parametrize('why', sorted(FALLBACKS))
def test_ssh_takes_the_flag_off_when_the_api_does_not(why):
    m = _manager(FALLBACKS[why])
    assert m._try_disable_native_ha_maintenance('pve1') is True
    assert m.ssh == ['ha-manager crm-command node-maintenance disable pve1']


def test_neither_way_leaves_the_node_without_the_flag():
    m, task = _manager(501, ssh_ok=False), _task()
    assert m._try_native_ha_maintenance('pve1', task) is False
    assert task.native_ha is False


def test_the_node_name_stays_one_path_segment():
    m = _manager(200)
    m._try_native_ha_maintenance('pve1/../../access', _task())
    assert m.puts[0][0] == 'https://10.0.0.1:8006/api2/json/nodes/pve1%2F..%2F..%2Faccess/maintenance'
