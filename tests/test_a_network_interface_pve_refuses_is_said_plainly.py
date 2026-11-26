"""A node network change Proxmox VE refuses comes back as a readable reason with PVE's status.

pve-manager 9.2.28 (PSA-2026-00077-1, PVE 9.3) refuses '${' and '<%' in the comments of an
interface: with python3-mako installed, ifupdown2 runs them as a template. The dialog sends the
comment PVE holds on every save, so a comment written before blocks that interface. What came
back was PVE's JSON body as the error text, always as a 500, and PVE only says "value does not
match the regex pattern".

The update and create of an interface now refuse such a comment with a 400 that says why, on a
node of 9.2.28 or newer and before anything is sent. pve-manager 9.2.38 refuses the same two
tags anywhere in ovs_options, which ifupdown2 renders with the rest of the file: those are
refused up front from 9.2.38 on. An older node, or one whose version cannot
be read, gets the change as before and PVE decides. Whatever PVE refuses goes out with PVE's
status and its reason as text (the fields it named in 'errors'), not as its raw body.

MK Nov 2026
"""
import json
import logging
import types

import pytest

from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'
IFACE = f'/api/clusters/{CID}/nodes/pve1/network/vmbr0'
CREATE = f'/api/clusters/{CID}/nodes/pve1/network'
TAGGED = 'uplink ${DC}'
PATTERN = 'value does not match the regex pattern'


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class _NetPve:
    """GET /nodes/<n>/version and the writes of /nodes/<n>/network, comments checked the way
    Network.pm checks them from 9.2.28 on"""

    def __init__(self, version='9.2.35', refuses_tags=True, answer=None):
        self.version = version
        self.refuses_tags = refuses_tags
        self.answer = answer
        self.writes, self.version_reads = [], 0

    def get(self, url, **kw):
        if url.endswith('/nodes/pve1/version'):
            self.version_reads += 1
            if self.version is None:
                return _Resp(500, {'data': None, 'message': 'proxy error'})
            return _Resp(200, {'data': {'version': self.version, 'release': '9.3', 'repoid': 'abc'}})
        return _Resp(404, {'data': None})

    def _write(self, method, url, data):
        self.writes.append((method, url.split('/api2/json', 1)[1], dict(data)))
        if self.answer is not None:
            return self.answer
        bad = {k: PATTERN for k in ('comments', 'comments6')
               if self.refuses_tags and ('${' in str(data.get(k, '')) or '<%' in str(data.get(k, '')))}
        if bad:
            return _Resp(400, {'data': None, 'message': 'Parameter verification failed.\n', 'errors': bad})
        return _Resp(200, {'data': None})

    def put(self, url, data=None, **kw):
        return self._write('PUT', url, data)

    def post(self, url, data=None, **kw):
        return self._write('POST', url, data)


def _manager(api, pve):
    pm = PegaProxManager.__new__(PegaProxManager)
    pm.is_connected = True
    pm.current_host = None
    pm.config = types.SimpleNamespace(name=CID, host='192.0.2.10', api_port=8006)
    pm.logger = logging.getLogger('test.network')
    pm._api_get, pm._api_put, pm._api_post = pve.get, pve.put, pve.post
    return api.set_manager(CID, pm)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def test_a_template_tag_is_refused_before_a_node_that_refuses_it_sees_it(api, admin):
    pve = _NetPve('9.2.35')
    _manager(api, pve)
    r = admin.put(IFACE, json={'type': 'bridge', 'comments': TAGGED, 'bridge_ports': 'eno1'})
    body = r.get_json()
    assert r.status_code == 400, body
    assert "refuses '${' and '<%' in the comment" in body['error'] and 'comments' in body['error']
    assert pve.writes == [] and pve.version_reads == 1
    r = admin.post(CREATE, json={'iface': 'vmbr9', 'type': 'bridge', 'comments6': 'v6 <% x %>'})
    assert r.status_code == 400 and '(comments6)' in r.get_json()['error']
    assert pve.writes == []


@pytest.mark.parametrize('version, said', [
    ('9.2.38', "in the OVS options of an interface, as ifupdown2 can run them as a template. Remove them (ovs_options)"),
    ('9.2.41', "in the comment and the OVS options of an interface, as ifupdown2 can run them as a "
               "template. Remove them (comments, ovs_options)"),
    ('9.2.37', "in the comment of an interface, as ifupdown2 can run them as a template. Remove them (comments)"),
])
def test_template_tags_in_the_ovs_options_are_refused_from_9_2_38_on(api, admin, version, said):
    pve = _NetPve(version)
    _manager(api, pve)
    ovs = {'type': 'OVSPort', 'ovs_bridge': 'vmbr1', 'ovs_options': 'tag=10 ${X}'}
    r = admin.put(IFACE, json={**ovs, **({'comments': TAGGED} if version != '9.2.38' else {})})
    body = r.get_json()
    assert r.status_code == 400, body
    assert body['error'] == f"Proxmox VE on pve1 (pve-manager {version}) refuses '${{' and '<%' {said} and save again."
    assert pve.writes == [] and pve.version_reads == 1
    r = admin.post(CREATE, json={'iface': 'ovsp1', **ovs, 'ovs_options': '<% x %>'})
    assert (r.status_code == 400) is (version != '9.2.37'), r.get_json()


def test_ovs_options_with_tags_go_to_a_node_before_9_2_38_as_before(api, admin):
    pve = _NetPve('9.2.37', refuses_tags=False)
    _manager(api, pve)
    r = admin.put(IFACE, json={'type': 'OVSPort', 'ovs_options': 'tag=10 ${X}'})
    assert r.status_code == 200, r.get_json()
    assert pve.writes == [('PUT', '/nodes/pve1/network/vmbr0', {'type': 'OVSPort', 'ovs_options': 'tag=10 ${X}'})]


@pytest.mark.parametrize('version', ['9.2.27', '8.4.14', None])
def test_an_older_node_or_one_that_cannot_say_gets_the_comment_as_before(api, admin, version):
    pve = _NetPve(version, refuses_tags=False)
    _manager(api, pve)
    r = admin.put(IFACE, json={'type': 'bridge', 'comments': TAGGED})
    assert r.status_code == 200, r.get_json()
    assert pve.writes == [('PUT', '/nodes/pve1/network/vmbr0', {'type': 'bridge', 'comments': TAGGED})]


def test_a_comment_without_tags_costs_no_version_read(api, admin):
    pve = _NetPve('9.2.35')
    _manager(api, pve)
    assert admin.put(IFACE, json={'type': 'bridge', 'comments': 'uplink $DC {a}'}).status_code == 200
    assert pve.version_reads == 0 and len(pve.writes) == 1


def test_what_pve_refuses_comes_back_as_its_reason_with_its_status(api, admin):
    """A 9.3 node whose version could not be read: PVE refuses, and says which field."""
    pve = _NetPve(None, refuses_tags=True)
    _manager(api, pve)
    r = admin.put(IFACE, json={'type': 'bridge', 'comments': TAGGED})
    body = r.get_json()
    assert r.status_code == 400, body
    assert body['error'] == f'comments: {PATTERN}'
    assert body['errors'] == {'comments': PATTERN}
    assert '{' not in body['error']


@pytest.mark.parametrize('answer, status, said', [
    (_Resp(500, {'data': None, 'message': "bridge 'vmbr0' does not exist\n"}), 500, 'vmbr0'),
    (_Resp(400, {'data': None, 'message': 'Parameter verification failed.\n',
                 'errors': {'cidr': "invalid format - unable to parse CIDR '10.0.0.300/24'\n"}}),
     400, "cidr: invalid format - unable to parse CIDR '10.0.0.300/24'"),
])
def test_a_create_pve_refuses_keeps_its_status_and_reason(api, admin, answer, status, said):
    pve = _NetPve('9.2.35', answer=answer)
    _manager(api, pve)
    r = admin.post(CREATE, json={'iface': 'vmbr9', 'type': 'bridge', 'cidr': '10.0.0.300/24'})
    error = r.get_json()['error']
    assert r.status_code == status and said in error, error
    assert not error.startswith('{') and 'data' not in error


def test_pve_refusing_the_stored_login_is_a_502(api, admin):
    pve = _NetPve('9.2.35', answer=_Resp(403, {'data': None, 'message': 'Permission check failed (/nodes/pve1, Sys.Modify)\n'}))
    _manager(api, pve)
    r = admin.put(IFACE, json={'type': 'bridge'})
    body = r.get_json()
    assert r.status_code == 502 and body['code'] == 'UPSTREAM_AUTH'
    assert body['error'].endswith('Permission check failed (/nodes/pve1, Sys.Modify)')
