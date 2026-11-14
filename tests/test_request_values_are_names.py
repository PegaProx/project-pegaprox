"""Names a cluster route takes from the query string or the body, on their way into the
Proxmox VE API path.

The request hook refused a '%', '?', '#', a backslash or a control character in the route
arguments of the cluster and PBS routes. The same names come from the query string and the
JSON body as well: a node, a target node, a storage, a guest type, a VMID. A route or the
manager behind it put them into the API path as they came, where a '/' adds path segments
and a '?' moves what the code wrote after the value into the query (on a POST or PUT,
Proxmox VE reads those parameters over the body). Some routes checked their value one by
one, the ISO sync did not: its source node went into the storage read of that node.

The hook refuses such a value now for every cluster route of a Proxmox VE cluster, with
the wording of the route arguments. XCP-ng and ESXi are left alone, as for the route
arguments. A list of guests in the body is no top-level value: the bulk migration checks
the node of each guest itself.
MK Nov 2026
"""
import io
import json
import types

import pytest
import requests
from requests.adapters import HTTPAdapter
from werkzeug.test import EnvironBuilder

from pegaprox.core.manager import PegaProxManager

from test_route_arguments_are_names import _ARG_RE, _plain, _url

# the keys whose string values go into an API path somewhere
NAMES = ('node', 'target_node', 'source_node', 'storage', 'target_storage', 'targetstorage',
         'target', 'vm_type', 'vmid', 'target_vmid')


class _PVE(HTTPAdapter):
    """Records the request line and answers like a small PVE."""
    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kw):
        self.sent.append((request.method, request.path_url))
        path = request.path_url.split('?')[0]
        if path.endswith('/storage'):
            data = [{'storage': 'local', 'content': 'iso,vztmpl', 'active': 1, 'shared': 0, 'type': 'dir'}]
        elif request.method == 'POST':
            data = 'UPID:n1:00001234:0000ABCD:65000000:qmigrate:100:root@pam:'
        else:
            data = []
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({'data': data}).encode()
        r.request = request
        return r


@pytest.fixture
def pve(api):
    pm = PegaProxManager.__new__(PegaProxManager)
    pm._api_token, pm._ticket, pm._csrf_token, pm._ssl_verify = None, 'TICKET', 'CSRF', False
    s = pm._create_session()
    rec = _PVE()
    s.mount('https://', rec)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.host, m.api_port = '10.0.0.1', 8006
    m.config = types.SimpleNamespace(name='c1', host='10.0.0.1')
    m._create_session.return_value = s
    m._api_get.side_effect = lambda url, **kw: s.get(url, **kw)
    m._api_post.side_effect = lambda url, **kw: s.post(url, **kw)
    api.set_manager('cluster_1', m)
    m.rec = rec
    return m


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


def _refused(r, what):
    assert r.status_code == 400 and r.get_json() == {'error': what}, (r.status_code, r.get_data(as_text=True))


# --- what reached the cluster before ----------------------------------------------------------

@pytest.mark.parametrize('node', ['n1/qemu/200/config?x=', 'n1/qemu/200/config#', 'n1%2Fqemu'])
def test_an_iso_sync_from_a_node_that_is_no_name_sends_nothing(admin, pve, node):
    pve._get_syncable_storage = types.MethodType(PegaProxManager._get_syncable_storage, pve)
    pve.get_storage_list = types.MethodType(PegaProxManager.get_storage_list, pve)
    body = {'storage': 'local', 'filename': 'debian-12.iso', 'content_type': 'iso'}
    _refused(admin.post('/api/clusters/cluster_1/iso-sync', json=dict(body, source_node=node)),
             'Invalid node name')
    assert pve.rec.sent == []
    # counterproof: the node's name is read as it is
    r = admin.post('/api/clusters/cluster_1/iso-sync', json=dict(body, source_node='pve-02.lab'))
    assert r.get_json() != {'error': 'Invalid node name'}, r.get_data(as_text=True)
    assert pve.rec.sent == [('GET', '/api2/json/nodes/pve-02.lab/storage')]


@pytest.mark.parametrize('node', ['n1/qemu/200/migrate?x=', 'n1/qemu/200/migrate#', 'n1 x'])
def test_a_bulk_migration_names_each_guests_node(admin, pve, monkeypatch, node):
    """The node of each guest goes into the path of its migrate call, the checks before it
    look at the VMID: 'n1/qemu/200/migrate?' moved guest 200 in the name of guest 100."""
    pve.migrate_vm_manual = types.MethodType(PegaProxManager.migrate_vm_manual, pve)
    pve._with_conntrack_state.return_value = False
    monkeypatch.setattr('pegaprox.api.vms._bulk_preflight', lambda *a, **k: {})
    monkeypatch.setattr('pegaprox.api.vms.push_immediate_update', lambda *a, **k: None)

    def move(node):
        return admin.post('/api/clusters/cluster_1/vms/bulk-migrate', json={
            'vms': [{'vmid': 100, 'node': node, 'type': 'qemu'}], 'target': 'pve-02'})
    _refused(move(node), 'Invalid node name')
    assert pve.rec.sent == []
    # counterproof: the guest's own node migrates it
    r = move('pve-01')
    assert r.status_code == 200 and r.get_json()['successful'] == 1, r.get_data(as_text=True)
    assert pve.rec.sent == [('POST', '/api2/json/nodes/pve-01/qemu/100/migrate')]


@pytest.mark.parametrize('content,sent', [
    ('iso&vmid=200', 'content=iso%26vmid%3D200'),
    ('iso#', 'content=iso%23'),
    ('iso', 'content=iso'),
])
def test_the_content_filter_of_a_storage_listing_is_one_parameter(admin, pve, content, sent):
    r = admin.get('/api/clusters/cluster_1/nodes/pve-01/storage/local/content',
                  query_string={'content': content})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.rec.sent == [('GET', f'/api2/json/nodes/pve-01/storage/local/content?{sent}')]
    pve.rec.sent.clear()
    assert admin.get('/api/clusters/cluster_1/nodes/pve-01/storage/local/content').status_code == 200
    assert pve.rec.sent == [('GET', '/api2/json/nodes/pve-01/storage/local/content')]


# --- the hook ------------------------------------------------------------------------------

@pytest.mark.parametrize('where', ['query', 'json'])
@pytest.mark.parametrize('key,value,label', [
    ('node', 'n1/qemu/200', 'node name'),
    ('target_node', 'n2?x=', 'node name'),
    ('source_node', 'n1#', 'node name'),
    ('storage', 'local/content', 'storage name'),
    ('target_storage', 'local%2Fx', 'storage name'),
    ('targetstorage', 'ceph\\x', 'storage name'),
    ('target', 'n2/qemu', 'target name'),
    ('vm_type', 'qemu/200', 'guest type'),
    ('vmid', '100/status/stop?', 'VMID'),
    ('target_vmid', '300\n', 'VMID'),
])
def test_a_name_that_would_not_stay_one_path_segment_is_refused(admin, pve, where, key, value, label):
    url = '/api/clusters/cluster_1/vms/pve-01/qemu/100/migrate'
    r = (admin.post(url, query_string={key: value}, json={'target': 'pve-02'}) if where == 'query'
         else admin.post(url, json={'target': 'pve-02', key: value} if key != 'target' else {key: value}))
    _refused(r, f'Invalid {label}')
    assert pve.rec.sent == [] and not pve.migrate_vm.called


def test_a_list_of_names_is_looked_at_item_by_item(admin, pve):
    url = '/api/clusters/cluster_1/vms/pve-01/qemu/100/migrate'
    _refused(admin.post(url, json={'target': ['pve-02', 'n2/qemu?']}), 'Invalid target name')
    _refused(admin.post(url + '?node=pve-01&node=n1/x', json={'target': 'pve-02'}), 'Invalid node name')


@pytest.mark.parametrize('body', [
    {'node': 'pve-02.lab', 'storage': 'local-lvm', 'target_storage': 'ceph_pool.1'},
    {'target_node': '7node', 'targetstorage': 'local-lvm:ceph,local:nfs-iso.2', 'vmid': 100},
    {'vmid': '100', 'target_vmid': 300, 'vm_type': 'lxc', 'source_node': 'n1'},
    # what is no string is left to the route
    {'node': None, 'storage': 7, 'target': {'node': 'a/b'}, 'vmid': [100, 101]},
])
def test_names_as_proxmox_ve_gives_them_pass_the_hook(api, monkeypatch, body):
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    url = '/api/clusters/cluster_1/vms/pve-01/qemu/100/migrate'
    assert _hooks_answer(api.app, url, 'POST', json_body=body) is None
    assert _hooks_answer(api.app, url, 'POST', query={k: v for k, v in body.items()
                                                      if isinstance(v, (str, int))}) is None


def test_an_xcpng_pool_and_an_esxi_host_keep_their_host_names(api, monkeypatch):
    """A cross-pool move names an XCP-ng host freely ('xen host #1'), and the XCP-ng pool
    puts no name into a URL path. The same body on a Proxmox VE cluster is refused."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    url = '/api/clusters/cluster_1/vms/xen1/qemu/100/migrate'
    body = {'target_node': 'xen host #1', 'target_storage': 'SR/local #2'}
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', cluster_type='proxmox'))
    assert _hooks_answer(api.app, url, 'POST', json_body=body) == 400
    for kind in ('xcpng', 'esxi'):
        api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', cluster_type=kind))
        assert _hooks_answer(api.app, url, 'POST', json_body=body) is None, kind
        assert _hooks_answer(api.app, url, 'POST', query={'node': 'xen host #1'}) is None, kind


def test_an_urlencoded_form_is_checked_and_keeps_its_body(api, monkeypatch):
    """A standby hands the body on as it came, so it is read from the cached bytes."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    url = '/api/clusters/cluster_1/vms/pve-01/qemu/100/migrate'
    form = 'application/x-www-form-urlencoded'
    assert _hooks_answer(api.app, url, 'POST', data='target=n2%2Fqemu', content_type=form) == 400
    with _context(api.app, url, 'POST', data='target=pve-02&online=1', content_type=form) as request:
        assert api.app.preprocess_request() is None
        assert request.get_data() == b'target=pve-02&online=1'


def test_a_multipart_body_is_left_to_the_route(api, monkeypatch):
    """Parsing an upload in a hook would spool the whole file before the caller is known;
    the upload route checks its node itself (test_api_path_request_values)."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    url = '/api/clusters/cluster_1/datastores/local/upload'
    with _context(api.app, url, 'POST', data={'node': 'n1/qemu/200'},
                  content_type='multipart/form-data') as request:
        assert api.app.preprocess_request() is None
        assert request.__dict__.get('_cached_data') is None and 'form' not in request.__dict__


class _CountedBody(io.RawIOBase):
    """A request body of `size` bytes that counts how much of it was read."""
    def __init__(self, size):
        self.size, self.taken = size, 0

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self.size - self.taken)
        b[:n] = b'a' * n
        self.taken += n
        return n


@pytest.mark.parametrize('length_told', [True, False], ids=['content-length', 'chunked'])
@pytest.mark.parametrize('ctype', ['application/json', 'application/x-www-form-urlencoded'])
def test_a_large_body_on_the_upload_route_is_not_read_before_the_sign_in(api, monkeypatch, ctype, length_told):
    """The upload route takes as much as an upload does. A JSON or form body sent there was
    read whole by the hook from a client not signed in yet, 12 MB here and up to the upload
    cap in a real request, before require_auth answered 401."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    size = 12 * 1024 * 1024
    env = EnvironBuilder(path='/api/clusters/cluster_1/datastores/local/upload', method='POST',
                         base_url='http://localhost', content_type=ctype,
                         headers={'X-Requested-With': 'XMLHttpRequest',
                                  'Origin': 'http://localhost'}).get_environ()
    body = _CountedBody(size)
    env['wsgi.input'] = io.BufferedReader(body)
    if length_told:
        env['CONTENT_LENGTH'] = str(size)
    else:
        env.pop('CONTENT_LENGTH', None)
        env['HTTP_TRANSFER_ENCODING'] = 'chunked'
        env['wsgi.input_terminated'] = True
    status = []
    b''.join(api.app.wsgi_app(env, lambda st, headers, *a: status.append(st)))
    assert body.taken < 64 * 1024, f'{body.taken} bytes read before the sign-in'
    assert status[0].startswith('401'), status


def test_a_body_nested_too_deep_is_left_to_the_route(api, monkeypatch):
    """The hook read it as no object; the caller who sent it is not signed in and gets the
    401 of require_auth, not a 500 of the JSON parser."""
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    url = '/api/clusters/cluster_1/vms/pve-01/qemu/100/migrate'
    deep = '[' * 50000 + ']' * 50000
    assert _hooks_answer(api.app, url, 'POST', data=deep, content_type='application/json') is None
    r = api.app.test_client().post(url, data=deep, content_type='application/json',
                                   headers={'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 401, r.get_data(as_text=True)[:200]


def test_routes_outside_the_cluster_routes_are_not_asked(api, monkeypatch):
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    assert _hooks_answer(api.app, '/api/cross-cluster-migrate/preflight', 'POST',
                         json_body={'target_node': 'n2/qemu'}) is None
    assert _hooks_answer(api.app, '/api/pbs/pbs1/datastores', 'GET', query={'node': 'a/b'}) is None


# --- every cluster route ---------------------------------------------------------------------

def _context(app, url, method, json_body=None, query=None, **kw):
    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'}
    if json_body is not None:
        kw['json'] = json_body
    return _ReqCtx(app.test_request_context(url, method=method, base_url='http://localhost',
                                            headers=headers, query_string=query, **kw))


class _ReqCtx:
    def __init__(self, ctx):
        self.ctx = ctx

    def __enter__(self):
        self.ctx.__enter__()
        from flask import request
        return request

    def __exit__(self, *exc):
        return self.ctx.__exit__(*exc)


def _hooks_answer(app, url, method, **kw):
    """What the request hooks answer, without running the route."""
    with _context(app, url, method, **kw):
        rv = app.preprocess_request()
        return None if rv is None else app.make_response(rv).status_code


def test_every_cluster_route_checks_the_names_of_its_query_and_body(api, monkeypatch):
    monkeypatch.setattr('pegaprox.app._check_api_rate_limit', lambda ip: True)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    keys = sorted(NAMES)
    checked, missed = 0, []
    for i, rule in enumerate(api.app.url_map.iter_rules()):
        if not rule.rule.startswith('/api/clusters/<cluster_id>/') or getattr(rule, 'websocket', False):
            continue
        args = {m.group(2): m.group(1) for m in _ARG_RE.finditer(rule.rule)}
        url = _url(rule.rule, {n: _plain(n, conv) for n, conv in args.items()})
        method = sorted(rule.methods - {'HEAD', 'OPTIONS'})[0]
        key = keys[i % len(keys)]
        assert _hooks_answer(api.app, url, method, query={key: 'pve-01'}) is None, rule.rule
        checked += 1
        if _hooks_answer(api.app, url, method, query={key: 'a/b?'}) != 400:
            missed.append(('query', method, rule.rule, key))
        if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            key = keys[(i + 3) % len(keys)]
            assert _hooks_answer(api.app, url, method, json_body={key: 'local-lvm'}) is None, rule.rule
            checked += 1
            if _hooks_answer(api.app, url, method, json_body={key: 'x#'}) != 400:
                missed.append(('json', method, rule.rule, key))
    assert checked > 600
    assert missed == [], missed
