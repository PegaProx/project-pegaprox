"""A failed node hosts read must not look like an empty /etc/hosts (#1164)."""

import logging
from types import SimpleNamespace

import pytest

from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager
from test_ha_ui import CLUSTER, NODE_METRICS, NODE_PATH, NODE_READS, VM, _App, _FakeServer, browser


def _pve(response=None, connected=True):
    manager = object.__new__(PegaProxManager)
    manager.is_connected = connected
    manager.current_host = None
    manager.config = SimpleNamespace(host='pve.example', api_port=8006)
    manager.logger = logging.getLogger(__name__)
    manager.connect_to_proxmox = lambda: False
    manager._api_get = lambda _url: response
    return manager


@pytest.mark.parametrize('response, expected', [
    (SimpleNamespace(status_code=200, json=lambda: {'data': {'data': '127.0.0.1 localhost\n'}}), '127.0.0.1 localhost\n'),
    (SimpleNamespace(status_code=200, json=lambda: {'data': {'data': ''}}), ''),
    (SimpleNamespace(status_code=403), None),
    (SimpleNamespace(status_code=200, json=lambda: {'data': {}}), None),
    (SimpleNamespace(status_code=200, json=lambda: {'data': None}), None),
])
def test_pve_hosts_distinguishes_content_empty_and_failed_reads(response, expected):
    assert _pve(response).get_node_hosts('pve1') == expected


def test_pve_hosts_connection_and_request_failures():
    assert _pve(connected=False).get_node_hosts('pve1') is None
    manager = _pve()
    manager._api_get = lambda _url: (_ for _ in ()).throw(ConnectionError('offline'))
    assert manager.get_node_hosts('pve1') is None


def test_xcpng_hosts_distinguishes_empty_file_from_ssh_failure():
    manager = object.__new__(XcpngManager)
    manager._ssh_exec = lambda *_args: (0, '', '')
    assert manager.get_node_hosts('host1') == ''
    manager._ssh_exec = lambda *_args: (1, '', 'unavailable')
    assert manager.get_node_hosts('host1') is None


def test_hosts_route_reports_failure_without_losing_valid_empty_file(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    user = seed.user('operator', role='user', tenant_id='acme',
                     permissions=['cluster.view', 'node.view'])
    manager = api.set_manager('cluster_1', api.make_fake_manager())
    path = '/api/clusters/cluster_1/nodes/pve1/hosts'

    manager.get_node_hosts.return_value = None
    failed = api.as_user(user).get(path)
    assert failed.status_code == 502
    assert failed.get_json() == {'error': 'Could not read hosts file from node'}

    manager.get_node_hosts.return_value = ''
    empty = api.as_user(user).get(path)
    assert empty.status_code == 200
    assert empty.get_json() == {'data': ''}

    manager.get_node_hosts.return_value = '127.0.0.1 localhost\n'
    populated = api.as_user(user).get(path)
    assert populated.status_code == 200
    assert populated.get_json() == {'data': '127.0.0.1 localhost\n'}


def test_hosts_route_keeps_cluster_access_gate(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=[])
    outsider = seed.user('outsider', role='user', tenant_id='other',
                         permissions=['cluster.view', 'node.view'])
    manager = api.set_manager('cluster_1', api.make_fake_manager(get_node_hosts='private'))
    response = api.as_user(outsider).get('/api/clusters/cluster_1/nodes/pve1/hosts')
    assert response.status_code == 403
    manager.get_node_hosts.assert_not_called()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('role', ['active', 'standby'])
@pytest.mark.parametrize('hosts_content', ['', '127.0.0.1 localhost\n'])
def test_failed_hosts_read_is_visible_and_retry_recovers_in_browser(browser, layout, role, hosts_content):
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/hosts')] = (502, {'error': 'Could not read hosts file from node'})
    server = _FakeServer(role=role, layout=layout, clusters=[CLUSTER], resources=[VM],
                         metrics=NODE_METRICS, extra=extra)
    app = _App(browser, server)
    try:
        page = app.page
        if layout == 'modern':
            page.get_by_text('Testi').first.click()
            page.locator('button[title="Node Configuration"]').first.click()
            page.locator('button', has_text='System').last.click()
        else:
            page.locator('.corp-tree-item', has_text='Testi').first.click()
            page.locator('.corp-tree-child', has_text='pve1').first.click()
            page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
            page.locator('.corp-subnav-item', has_text='Hosts File').first.click()

        alert = page.get_by_role('alert').filter(has_text='Could not read the hosts file from this node')
        alert.wait_for(timeout=8000)
        assert 'No data' not in alert.inner_text()
        if layout == 'modern':
            hosts_panel = page.get_by_text('/etc/hosts', exact=True).locator('../..')
            assert hosts_panel.locator('textarea').is_disabled()
        else:
            assert page.get_by_role('button', name='Edit').last.is_disabled()

        server.extra[('GET', NODE_PATH + '/hosts')] = (200, {'data': hosts_content})
        retry = alert.get_by_role('button', name='Retry')
        assert retry.is_enabled()
        retry.click()
        alert.wait_for(state='hidden', timeout=8000)
        if layout == 'modern':
            assert hosts_panel.locator('textarea').input_value() == hosts_content
        else:
            hosts_panel = page.get_by_text('Hosts File', exact=True).last.locator('../..')
            assert hosts_panel.locator('pre').inner_text() == hosts_content
        assert not [error for error in app.errors if 'pageerror' in error], app.errors
    finally:
        app.ctx.close()
