"""Arguments of the cluster and PBS routes that go into the API path of the cluster.

The WSGI server decodes the request path once, so '/vms/n1%252Fqemu%252F200%252Fconfig%3F...'
gave the route the node 'n1%2Fqemu%2F200%2Fconfig?...'. Put into the Proxmox VE path, the
'?' moved the rest of the path the code wrote into the query, and Proxmox VE decodes the
'%2F' into separators again: a start of VM 100 went out as a config write of VM 200, with the
cluster's own login. No '..' is in there, so the session's path check let it pass.

An argument of a cluster or PBS route that holds a '%', '?', '#', a backslash or a control
character is refused before the route runs now. Names as the clusters give them go through,
and so do the host names of an XCP-ng pool, which never go into a URL path.
MK Nov 2026
"""
import json
import re
import types
from urllib.parse import quote

import pytest
import requests
from requests.adapters import HTTPAdapter

import pegaprox.globals as ppglobals
from pegaprox.core.manager import PegaProxManager

from test_audit_round5_batch13 import _seed_pool_membership

# what reaches the route as 'n1%2Fqemu%2F200%2Fconfig?description=' once the path is decoded
ODD_NODE = 'n1%252Fqemu%252F200%252Fconfig%3Fdescription='


class _PVE(HTTPAdapter):
    """Records the request line and answers every call with a task id."""
    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kw):
        self.sent.append((request.method, request.path_url))
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({'data': 'UPID:n1:00001234:0000ABCD:65000000:qmstart:100:root@pam:'}).encode()
        r.request = request
        return r


@pytest.fixture
def pve(api):
    """A fake cluster whose vm_action is the real one, sending through the session
    _create_session builds, with the recording transport under it."""
    pm = PegaProxManager.__new__(PegaProxManager)
    pm._api_token, pm._ticket, pm._csrf_token, pm._ssl_verify = None, 'TICKET', 'CSRF', False
    s = pm._create_session()
    rec = _PVE()
    s.mount('https://', rec)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.host, m.api_port = '10.0.0.1', 8006
    m.config.user = 'root@pam'
    m._create_session.return_value = s
    m._api_post.side_effect = lambda url, **kw: s.post(url, **kw)
    m.vm_action = types.MethodType(PegaProxManager.vm_action, m)
    for name in ('update_vm_config', 'create_snapshot', 'delete_snapshot', 'delete_node_network',
                 '_api_delete'):
        getattr(m, name).return_value = {'success': True}
    m.get_vm_config.return_value = {'success': True, 'config': {}}
    api.set_manager('cluster_1', m)
    m.rec = rec
    return m


def _tenant_user(seed, perms):
    """A user confined to pool_1 (VM 100) of cluster_1 with `perms` there."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'] + perms)
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'] + perms)
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    return u


def _odd_calls(m):
    return [c for c in m.mock_calls if '%2F' in str(c) or '?' in str(c)]


def test_a_power_action_on_an_encoded_node_reaches_no_cluster(api, seed, pve):
    c = api.as_user(_tenant_user(seed, ['vm.start']))

    r = c.post(f'/api/clusters/cluster_1/vms/{ODD_NODE}/qemu/100/start')
    assert (r.status_code, pve.rec.sent) == (400, []), r.get_data(as_text=True)
    assert r.get_json() == {'error': 'Invalid node name'}

    # the node as the cluster names it
    r = c.post('/api/clusters/cluster_1/vms/pve-node1/qemu/100/start')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.rec.sent == [('POST', '/api2/json/nodes/pve-node1/qemu/100/status/start')]


@pytest.mark.parametrize('method,suffix', [
    ('put', '/qemu/100/config'),
    ('post', '/qemu/100/snapshots'),
    ('delete', '/qemu/100/snapshots/before-update'),
])
def test_guest_writes_on_an_encoded_node_reach_no_cluster(api, seed, pve, method, suffix):
    c = api.as_user(_tenant_user(seed, ['vm.config', 'vm.snapshot']))
    r = getattr(c, method)(f'/api/clusters/cluster_1/vms/{ODD_NODE}{suffix}',
                           json={'description': 'x', 'snapname': 'snap1'})
    assert (r.status_code, _odd_calls(pve), pve.rec.sent) == (400, [], []), r.get_data(as_text=True)


@pytest.mark.parametrize('path', [
    # a plain '?' in the node
    '/api/clusters/cluster_1/vms/n1%3Fdescription=/qemu/100/start',
    # a '#' that would cut off the rest of the path
    '/api/clusters/cluster_1/vms/n1%23/qemu/100/start',
    # a backslash, a newline
    '/api/clusters/cluster_1/vms/n1%5Cx/qemu/100/start',
    '/api/clusters/cluster_1/vms/n1%0A/qemu/100/start',
])
def test_a_node_with_a_query_fragment_or_control_character_is_refused(api, seed, pve, path):
    c = api.as_user(_tenant_user(seed, ['vm.start']))
    r = c.post(path)
    assert (r.status_code, pve.rec.sent) == (400, []), r.get_data(as_text=True)


# what reaches the route as 'x1%2Fy?'
ODD = 'x1%252Fy%3F'


@pytest.mark.parametrize('method,path', [
    ('get', f'/api/clusters/cluster_1/nodes/pve-node1/storage/local{ODD}/content'),
    ('delete', f'/api/clusters/cluster_1/vms/pve-node1/qemu/100/snapshots/s1{ODD}'),
    ('delete', f'/api/clusters/cluster_1/nodes/pve-node1/network/vmbr0{ODD}'),
    ('delete', f'/api/clusters/cluster_1/vms/pve-node1/qemu/100/firewall/aliases/a{ODD}'),
    ('delete', f'/api/clusters/cluster_1/proxmox-ha/groups/g{ODD}'),
    # a guest type that is none
    ('put', f'/api/clusters/cluster_1/vms/pve-node1/qemu{ODD}/100/config'),
])
def test_other_names_with_an_encoded_slash_reach_no_cluster(api, seed, pve, method, path):
    admin = api.as_user(seed.user('root1', role='admin'))
    r = getattr(admin, method)(path, json={'description': 'x'})
    assert (r.status_code, _odd_calls(pve), pve.rec.sent) == (400, [], []), r.get_data(as_text=True)


def test_a_pbs_datastore_with_an_encoded_slash_is_refused(api, seed):
    from unittest.mock import MagicMock
    pm = MagicMock()
    pm.connected = True
    pm.linked_clusters = []
    pm.start_gc.return_value = {'data': 'UPID:pbs1:00001234:0000ABCD:65000000:garbage_collection:ds1:root@pam:'}
    ppglobals.pbs_managers['pbs1'] = pm
    try:
        admin = api.as_user(seed.user('root1', role='admin'))
        r = admin.post(f'/api/pbs/pbs1/datastores/ds1{ODD}/gc')
        assert (r.status_code, _odd_calls(pm)) == (400, []), r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.pop('pbs1', None)


# -- every argument of every cluster and PBS route -------------------------------------------

_ARG_RE = re.compile(r'<(?:(\w+):)?(\w+)>')


def _plain(name, conv):
    if conv == 'int':
        return '100'
    if conv == 'path':
        return 'x'
    return {'cluster_id': 'cluster_1', 'node': 'pve-node1', 'node_name': 'pve-node1',
            'target_node': 'pve-node2', 'vm_type': 'qemu', 'vmtype': 'qemu',
            'vmid': '100'}.get(name, 'name-1')


def _url(rule, values):
    return _ARG_RE.sub(lambda mo: quote(values[mo.group(2)], safe=''), rule)


def _hooks_answer(app, rule, method, url, websocket=False):
    """What the request hooks answer for `url`, without running the route."""
    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'}
    if websocket:
        headers.update({'Connection': 'Upgrade', 'Upgrade': 'websocket'})
    with app.test_request_context(url, method=method, base_url='http://localhost', headers=headers):
        from flask import request
        assert request.url_rule is not None and request.url_rule.rule == rule, (url, request.url_rule)
        rv = app.preprocess_request()
        return None if rv is None else app.make_response(rv).status_code


def test_every_argument_of_a_cluster_or_pbs_route_is_checked(api, monkeypatch):
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    app = api.app
    checked, missed = 0, []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith(('/api/clusters/', '/api/pbs/')):
            continue
        args = {m.group(2): m.group(1) for m in _ARG_RE.finditer(rule.rule)}
        names = [n for n, conv in args.items() if conv not in ('int', 'path') and n != 'subject_id']
        if not names:
            continue
        method = sorted(rule.methods - {'HEAD', 'OPTIONS'})[0]
        plain = {n: _plain(n, conv) for n, conv in args.items()}
        # the names a cluster gives go through the hooks
        ws = bool(getattr(rule, 'websocket', False))
        assert _hooks_answer(app, rule.rule, method, _url(rule.rule, plain), ws) is None, rule.rule
        for name in names:
            # quoted once more here: the route sees 'a%2Fb?'
            url = _url(rule.rule, dict(plain, **{name: 'a%2Fb?'}))
            checked += 1
            if _hooks_answer(app, rule.rule, method, url, ws) != 400:
                missed.append((method, rule.rule, name))
    assert checked > 400
    assert missed == [], missed


def test_an_xcpng_pool_keeps_its_host_names(api, monkeypatch):
    """XCP-ng names a host freely ('xen host #1') and puts it into no URL path. The same
    name on a Proxmox VE cluster is refused."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    rule = '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/<action>'
    url = '/api/clusters/cluster_1/vms/xen%20host%20%231/qemu/100/start'
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', cluster_type='proxmox'))
    assert _hooks_answer(api.app, rule, 'POST', url) == 400
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', cluster_type='xcpng'))
    assert _hooks_answer(api.app, rule, 'POST', url) is None
