"""A failed node DNS read must not look like a node without DNS (#1163). The managers and the
route; what the browser shows is in test_node_dns_read_ui_1163.py."""

import logging
from types import SimpleNamespace

import pytest
import requests

from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager

DNS_PATH = '/api/clusters/cluster_1/nodes/pve1/dns'


def _answer(status, body=None, text=''):
    def _json():
        if isinstance(body, Exception):
            raise body
        return body
    return SimpleNamespace(status_code=status, text=text, json=_json)


def _pve(response=None, connected=True, raises=None):
    manager = object.__new__(PegaProxManager)
    manager.is_connected = connected
    manager.current_host = None
    manager.config = SimpleNamespace(host='pve.example', api_port=8006)
    manager.logger = logging.getLogger(__name__)
    manager.connect_to_proxmox = lambda: False

    def _get(_url):
        if raises is not None:
            raise raises
        return response
    manager._api_get = _get
    return manager


# --- the manager: content, a real empty config, and every way the read can fail ---

@pytest.mark.parametrize('body', [
    {'data': {'search': 'lan', 'dns1': '1.1.1.1', 'dns2': '9.9.9.9'}},
    {'data': {}},
])
def test_pve_dns_read_hands_back_what_proxmox_has(body):
    assert _pve(_answer(200, body)).get_node_dns('pve1') == body['data']


@pytest.mark.parametrize('response, status', [
    (_answer(403, text='{"data":null}'), 403),
    (_answer(401), 401),
    (_answer(500, text='{"data":null}'), 500),
    (_answer(595), 595),
    (_answer(200, {'data': None}), None),
    (_answer(200, {}), None),
    (_answer(200, ValueError('not json')), None),
])
def test_pve_dns_failed_read_is_an_error_not_an_empty_config(response, status):
    result = _pve(response).get_node_dns('pve1')
    assert result.get('error')
    assert result['upstream_status'] == status
    assert not {'search', 'dns1', 'dns2', 'dns3'} & set(result)


def test_pve_dns_says_unreachable_for_a_node_pveproxy_cannot_reach():
    assert 'unreachable' in _pve(_answer(595)).get_node_dns('pve1')['error']


def test_pve_dns_no_connection_and_no_answer_are_errors():
    offline = _pve(connected=False).get_node_dns('pve1')
    assert offline == {'error': 'The cluster is not connected', 'upstream_status': None}
    silent = _pve(raises=requests.exceptions.ConnectTimeout('timed out')).get_node_dns('pve1')
    assert silent == {'error': 'Proxmox VE did not answer', 'upstream_status': None}


def _xcp(rc, out='', err=''):
    manager = object.__new__(XcpngManager)
    manager._ssh_exec = lambda *_args, **_kw: (rc, out, err)
    return manager


def test_xcpng_dns_distinguishes_an_empty_resolv_conf_from_a_failed_read():
    assert _xcp(0, 'search lan\nnameserver 1.1.1.1\n').get_node_dns('host1') == {'search': 'lan', 'dns1': '1.1.1.1'}
    assert _xcp(0, '').get_node_dns('host1') == {'search': ''}
    no_file = _xcp(1).get_node_dns('host1')
    assert no_file['error'] and no_file['upstream_status'] is None
    no_ssh = _xcp(-1, err='SSH connection failed').get_node_dns('host1')
    assert 'SSH' in no_ssh['error'] and no_ssh['upstream_status'] is None


# --- the route, over the real manager method ---

def _operator(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('operator', role='user', tenant_id='acme', permissions=['cluster.view', 'node.view'])


def _route_over(api, pve):
    manager = api.set_manager('cluster_1', api.make_fake_manager())
    manager.get_node_dns.side_effect = pve.get_node_dns
    return manager


@pytest.mark.parametrize('body', [
    {'data': {'search': 'lan', 'dns1': '1.1.1.1'}},
    {'data': {}},
])
def test_dns_route_answers_200_for_a_read_that_worked(api, seed, body):
    user = _operator(seed)
    _route_over(api, _pve(_answer(200, body)))
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 200
    assert response.get_json() == body['data']


@pytest.mark.parametrize('pve, said, upstream', [
    (_pve(_answer(500, text='{"data":null}')), 'Proxmox VE answered HTTP 500', 500),
    (_pve(_answer(595)), 'The node is unreachable (HTTP 595)', 595),
    (_pve(raises=requests.exceptions.ConnectionError('refused')), 'Proxmox VE did not answer', None),
    (_pve(connected=False), 'The cluster is not connected', None),
    (_pve(_answer(200, {'data': None})), 'Proxmox VE sent no DNS settings', None),
])
def test_dns_route_answers_502_for_each_failed_read(api, seed, pve, said, upstream):
    user = _operator(seed)
    _route_over(api, pve)
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 502
    assert response.get_json() == {'error': said, 'upstream_status': upstream}


@pytest.mark.parametrize('status, said', [
    (403, 'does not allow this with the stored credentials (HTTP 403): reading the DNS settings needs Sys.Audit'),
    (401, 'refused the stored credentials (HTTP 401)'),
])
def test_dns_route_reports_a_refused_read_as_upstream_auth_not_as_the_callers_403(api, seed, status, said):
    # a 401/403 handed on as it came reads as the caller's own session or permission (#1142)
    user = _operator(seed)
    _route_over(api, _pve(_answer(status, text='{"data":null}')))
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 502
    body = response.get_json()
    assert body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == status
    assert said in body['error']


def test_dns_route_does_not_echo_what_the_connection_error_said(api, seed):
    user = _operator(seed)
    leak = requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='10.9.8.7', port=8006): Cookie PVEAuthCookie=PVE:root@pam:SECRETTICKET")
    _route_over(api, _pve(raises=leak))
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 502
    text = response.get_data(as_text=True)
    assert '10.9.8.7' not in text and 'SECRETTICKET' not in text


def test_dns_route_over_an_xcpng_host_that_could_not_be_read(api, seed):
    user = _operator(seed)
    _route_over(api, _xcp(-1, err='SSH connection failed'))
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 502
    assert response.get_json() == {'error': 'The host could not be reached over SSH', 'upstream_status': None}


def test_dns_route_for_a_cluster_type_without_dns_settings(api, seed):
    user = _operator(seed)
    manager = api.set_manager('cluster_1', api.make_fake_manager(cluster_type='esxi'))
    del manager.get_node_dns
    response = api.as_user(user).get(DNS_PATH)
    assert response.status_code == 501
    assert 'not available' in response.get_json()['error']


def test_dns_route_keeps_cluster_access_gate(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=[])
    outsider = seed.user('outsider', role='user', tenant_id='other',
                         permissions=['cluster.view', 'node.view'])
    manager = api.set_manager('cluster_1', api.make_fake_manager(get_node_dns={'search': 'private'}))
    response = api.as_user(outsider).get(DNS_PATH)
    assert response.status_code == 403
    manager.get_node_dns.assert_not_called()
