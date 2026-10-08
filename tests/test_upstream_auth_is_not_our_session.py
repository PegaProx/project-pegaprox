"""A 401 or 403 of a system behind PegaProx is never PegaProx's own (#1142).

Change the password of a registered ESXi server to a wrong one and every route of that
server answered the browser with the server's own status: jsonify(result), status_code.
ESXi said 401, so the browser got a 401, and authFetch read every 401 as the PegaProx
session running out. The user was signed off at each click on the server and could not
reach its settings to fix or remove it.

The same handing-on sat in about ninety Proxmox VE passthroughs (firewall, SDN, Ceph,
storage, backup jobs, ...), in the PBS routes and in the HA resources plugin: a cluster
whose stored password or API token stopped working did the same thing. And the node join
check answered a wrong SSH password with a literal 401.

Now: an upstream 401/403 is a 502 with code UPSTREAM_AUTH and a sentence saying whose
credentials were refused. Every other upstream status is as it was (an ESXi 5xx is a 502).
PegaProx's own 401 for a missing, expired or revoked session or token carries one of the
codes the browser knows (web/src/api_errors.js SESSION_LOST), and the browser acts on
nothing else. Each test below also shows the upstream really said 401/403, so a 502 cannot
pass for the wrong reason. MK Oct 2026
"""
import ast
import os
import re
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.vmware import VMwareManager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VMW = 'esx1'
CID = 'c1'


class _Resp:
    def __init__(self, status, body=None, text=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = text if text is not None else ('{"error_type":"UNAUTHENTICATED"}' if status == 401 else '')
        self.headers = {'Content-Type': 'application/json'}
        self.content = self.text.encode()

    def json(self):
        return self._body


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


@pytest.fixture
def esxi(api, monkeypatch):
    """A real VMwareManager whose server answers every call with `status` (401 by default)."""
    import requests
    state = {'status': 401, 'calls': []}

    def _answer(method, url, **kw):
        state['calls'].append((method, url))
        if state['status'] == 200:
            if url.endswith('/api/session'):
                return _Resp(201, 'sess-1')
            return _Resp(200, [{'vm': 'vm-1', 'name': 'web01', 'power_state': 'POWERED_ON'}])
        return _Resp(state['status'])

    monkeypatch.setattr(requests, 'get', lambda url, **kw: _answer('GET', url, **kw))
    monkeypatch.setattr(requests, 'post', lambda url, **kw: _answer('POST', url, **kw))
    monkeypatch.setattr(requests, 'request', lambda method, url, **kw: _answer(method, url, **kw))
    mgr = VMwareManager(VMW, {'name': 'lab esxi', 'host': 'esx1.lab', 'username': 'root',
                              'password': 'changed-and-wrong', 'server_type': 'esxi'})
    ppglobals.vmware_managers[VMW] = mgr
    state['mgr'] = mgr
    return state


ESXI_READS = [f'/api/vmware/{VMW}/vms', f'/api/vmware/{VMW}/hosts', f'/api/vmware/{VMW}/datastores',
              f'/api/vmware/{VMW}/networks', f'/api/vmware/{VMW}/vms/vm-1', f'/api/vmware/{VMW}/datacenters',
              f'/api/vmware/{VMW}/clusters']


def _fresh(mgr):
    # every request reconnects as on the first click, no cooldown of the one before
    mgr._last_connect_attempt = 0
    mgr._last_connect_error_type = ''


# --- ESXi ----------------------------------------------------------------------------------

@pytest.mark.parametrize('path', ESXI_READS)
def test_an_esxi_server_refusing_its_password_is_a_502_not_our_401(admin, esxi, path):
    _fresh(esxi['mgr'])
    r = admin.get(path)
    body = r.get_json()
    assert r.status_code == 502, (r.status_code, body)
    assert body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == 401
    assert body['error'].startswith('The ESXi server refused the stored credentials (HTTP 401)')
    # counterproof: the server really said 401, and so does the manager to the route
    assert esxi['calls'] and esxi['mgr'].api_get('/api/vcenter/vm')['status_code'] == 401


def test_a_power_action_refused_by_esxi_is_a_502(admin, esxi):
    r = admin.post(f'/api/vmware/{VMW}/vms/vm-1/power/start')
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH'
    assert ('POST', 'https://esx1.lab:443/api/vcenter/vm/vm-1/power/start') in esxi['calls']


def test_a_403_of_esxi_is_a_502_as_well(admin, esxi):
    esxi['status'] = 403
    _fresh(esxi['mgr'])
    r = admin.get(f'/api/vmware/{VMW}/vms')
    body = r.get_json()
    assert r.status_code == 502 and body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == 403
    assert 'does not allow this with the stored credentials (HTTP 403)' in body['error']
    assert esxi['mgr'].api_get('/api/vcenter/vm')['status_code'] == 403


def test_the_same_server_answering_again_is_a_plain_200(admin, esxi):
    """Counterproof for the path itself: with the password right the route lists the VMs."""
    esxi['status'] = 200
    _fresh(esxi['mgr'])
    r = admin.get(f'/api/vmware/{VMW}/vms')
    assert r.status_code == 200, r.get_json()
    assert [v['name'] for v in r.get_json()] == ['web01']


@pytest.mark.parametrize('upstream,want', [(401, 502), (403, 502), (500, 502), (503, 502),
                                           (404, 404), (400, 400), (None, 500)])
def test_every_other_esxi_status_keeps_a_sane_mapping(admin, api, upstream, want):
    fake = MagicMock(name='esxi')
    fake.linked_clusters = []
    fake.get_datastore_detail.return_value = (
        {'error': 'boom'} if upstream is None else {'error': f'HTTP {upstream}: x', 'status_code': upstream})
    ppglobals.vmware_managers[VMW] = fake
    r = admin.get(f'/api/vmware/{VMW}/datastores/ds-1')
    assert r.status_code == want, (upstream, r.status_code, r.get_json())
    assert (r.get_json().get('code') == 'UPSTREAM_AUTH') == (upstream in (401, 403))


def test_our_own_missing_session_is_still_a_401_auth_required(api, esxi):
    r = api.anon().get(f'/api/vmware/{VMW}/vms')
    assert r.status_code == 401 and r.get_json()['code'] == 'AUTH_REQUIRED'
    # and the server was never asked
    assert esxi['calls'] == []


def test_a_disabled_account_is_still_a_401_with_its_code(api, seed, esxi):
    seed.user('gone', role='admin', enabled=False)
    r = api.as_user({'username': 'gone', 'role': 'admin'}).get(f'/api/vmware/{VMW}/vms')
    assert r.status_code == 401 and r.get_json()['code'] == 'ACCOUNT_DISABLED'


# --- Proxmox VE, PBS, the HA plugin, the node join check ------------------------------------

@pytest.fixture
def pve(api):
    fake = api.make_fake_manager(CID)
    fake.is_connected = True
    fake.host, fake.api_port = 'pve1.lab', 8006
    fake._api_token = None
    fake.config.name = 'lab'
    session = fake._create_session.return_value
    api.set_manager(CID, fake)
    return session


PVE_ROUTES = [
    ('get', f'/api/clusters/{CID}/datacenter/sdn/zones', 'get'),                  # datacenter.py
    ('put', f'/api/clusters/{CID}/datacenter/firewall/options', 'put'),           # vms.py
    ('post', f'/api/clusters/{CID}/nodes/pve1/ceph/osd', 'post'),                 # ceph.py
    ('get', f'/api/clusters/{CID}/nodes/pve1/ceph/status', 'get'),                # ceph.py, empty body
    ('delete', f'/api/clusters/{CID}/datacenter/backup/job-1', 'delete'),         # storage.py
]


@pytest.mark.parametrize('upstream', [401, 403])
@pytest.mark.parametrize('verb,path,call', PVE_ROUTES)
def test_proxmox_refusing_the_stored_login_is_a_502(admin, pve, verb, path, call, upstream):
    getattr(pve, call).return_value = _Resp(upstream, {'message': 'authentication failure'},
                                            text='{"message":"authentication failure"}')
    r = getattr(admin, verb)(path, json={'dev': '/dev/sdb'} if verb != 'get' else None)
    assert r.status_code == 502, (path, r.status_code, r.get_json())
    assert getattr(pve, call).called, 'the cluster was not asked: a 502 for the wrong reason'
    if 'ceph/status' not in path:
        body = r.get_json()
        assert body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == upstream
        assert body['error'].startswith(f'Proxmox VE ') and f'(HTTP {upstream})' in body['error']


@pytest.mark.parametrize('verb,path,call', PVE_ROUTES)
def test_other_proxmox_statuses_go_out_as_they_came(admin, pve, verb, path, call):
    """Counterproof: only the 401/403 changed. A 400 of Proxmox is still the caller's 400."""
    getattr(pve, call).return_value = _Resp(400, {'message': 'bad value'}, text='{"message":"bad value"}')
    r = getattr(admin, verb)(path, json={'dev': '/dev/sdb'} if verb != 'get' else None)
    assert r.status_code == 400, (path, r.status_code, r.get_json())
    assert (r.get_json() or {}).get('code') != 'UPSTREAM_AUTH'


@pytest.fixture
def pbs(api):
    fake = MagicMock(name='pbs')
    fake.linked_clusters = []
    ppglobals.pbs_managers['p1'] = fake
    return fake


@pytest.mark.parametrize('upstream,want', [(401, 502), (403, 502), (None, 502), (404, 404)])
def test_a_pbs_server_refusing_its_login_is_a_502(admin, pbs, upstream, want):
    pbs.get_groups.return_value = ({'error': 'PBS unreachable'} if upstream is None
                                   else {'error': f'HTTP {upstream}', 'status_code': upstream})
    r = admin.get('/api/pbs/p1/datastores/store1/groups')
    assert r.status_code == want, (upstream, r.get_json())
    if upstream in (401, 403):
        assert r.get_json()['error'].startswith('The PBS server ')
        assert r.get_json()['code'] == 'UPSTREAM_AUTH'


def test_the_ha_plugin_hands_on_no_401(api):
    # loaded the way the plugin loader does: its directory name has a hyphen
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'proxmox_ha_upstream_test', os.path.join(ROOT, 'plugins', 'proxmox-ha', '__init__.py'))
    ha_plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ha_plugin)
    with api.app.test_request_context('/'):
        resp, status = ha_plugin._proxmox_failed(_Resp(401, {'message': 'no ticket'}))
        assert status == 502 and resp.get_json()['code'] == 'UPSTREAM_AUTH'
        assert resp.get_json()['detail'] == 'no ticket'
        # counterproof: a 404 of Proxmox is still a 404, a 500 still the 502 it was
        assert ha_plugin._proxmox_failed(_Resp(404, {'message': 'x'}))[1] == 404
        assert ha_plugin._proxmox_failed(_Resp(500, {'message': 'x'}))[1] == 502


def test_a_wrong_ssh_password_at_the_node_join_check_is_not_a_401(admin, pve, monkeypatch):
    import pegaprox.api.vms as vms

    class AuthFailed(Exception):
        pass

    client = MagicMock()
    client.connect.side_effect = AuthFailed('bad password')
    fake_paramiko = MagicMock(AuthenticationException=AuthFailed, SSHException=type('SSHErr', (Exception,), {}))
    fake_paramiko.SSHClient.return_value = client
    monkeypatch.setattr(vms, 'get_paramiko', lambda: fake_paramiko)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda *a, **k: None)
    r = admin.post(f'/api/clusters/{CID}/nodes/join/test',
                   json={'node_ip': '10.0.0.5', 'username': 'root', 'password': 'wrong'})
    assert client.connect.called, 'the node was not asked'
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH'
    assert r.get_json()['error'] == 'Authentication failed. Check username/password.'


def test_the_helper():
    from flask import Flask
    from pegaprox.api.helpers import upstream_failure, upstream_status
    with Flask(__name__).test_request_context('/'):
        resp, status = upstream_failure(401, 'authentication failure')
        assert status == 502 and resp.get_json() == {
            'error': 'Proxmox VE refused the stored credentials (HTTP 401): authentication failure',
            'code': 'UPSTREAM_AUTH', 'upstream_status': 401}
        resp, status = upstream_failure(500, 'VM 100 is locked', pve_status=500)
        assert status == 500 and resp.get_json() == {'error': 'VM 100 is locked', 'pve_status': 500}
        assert upstream_failure(None, 'x', default=502)[1] == 502
    assert [upstream_status(s) for s in (401, 403, 404, 500, None)] == [502, 502, 404, 500, 500]


# --- the whole backend, read ------------------------------------------------------------------

def _modules():
    out = []
    for d in ('pegaprox/api', 'plugins'):
        for dp, _dn, fn in os.walk(os.path.join(ROOT, d)):
            out += [os.path.join(dp, f) for f in fn if f.endswith('.py')]
    return sorted(out)


def test_no_route_answers_with_a_status_read_off_an_upstream_answer():
    """Every `return <body>, <status>` and Response(status=...) whose status comes from an
    upstream answer (resp.status_code, result['status_code'], got['status']) has to go
    through upstream_failure / upstream_status. Before #1142 this listed 120 places."""
    upstream = re.compile(r"status_code|\[['\"]status['\"]\]|get\(['\"]status['\"]")
    found = []
    for p in _modules():
        src = open(p, encoding='utf-8').read()
        for node in ast.walk(ast.parse(src)):
            exprs = []
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2:
                exprs.append(node.value.elts[1])
            if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'Response':
                exprs += [k.value for k in node.keywords if k.arg == 'status']
            for e in exprs:
                if isinstance(e, (ast.JoinedStr, ast.Constant)):
                    continue    # (ok, message) of a helper, not a status
                seg = ast.get_source_segment(src, e) or ''
                if upstream.search(seg) and not seg.startswith(('upstream_status(', 'upstream_failure(')):
                    found.append(f'{os.path.relpath(p, ROOT)}:{e.lineno}: {seg}')
    # one of our own: a status computed from a message, not taken from an answer
    found = [f for f in found if not f.startswith('pegaprox/api/vms.py') or not f.endswith(': status_code')]
    assert not found, '\n'.join(found)


def _routes(fn):
    return [d.args[0].value for d in fn.decorator_list
            if isinstance(d, ast.Call) and getattr(d.func, 'attr', '') == 'route' and d.args
            and isinstance(d.args[0], ast.Constant)]


# 401s that are about something else than the session, and say so in their words: the
# caller's own password typed again, and the key of the public status page
NOT_A_SESSION = {('pegaprox/api/clusters.py', 'reconfigure_cluster'), ('pegaprox/api/nodes.py', 'run_custom_script'),
                 ('pegaprox/api/settings.py', 'backup_config'), ('pegaprox/api/settings.py', 'restore_config'),
                 ('plugins/status_page/__init__.py', '_check_key')}


def _session_lost_codes():
    src = open(os.path.join(ROOT, 'web', 'src', 'api_errors.js'), encoding='utf-8').read()
    return set(re.findall(r"'([A-Z_]+)'", re.search(r'SESSION_LOST: \[(.*?)\]', src, re.S).group(1)))


def test_every_401_of_a_lost_session_carries_a_code_the_browser_knows():
    known = _session_lost_codes()
    assert {'AUTH_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_DISABLED', 'HA_FORWARD_STALE_SIGN_IN'} <= known
    bad, seen = [], set()
    for p in _modules() + [os.path.join(ROOT, 'pegaprox', 'utils', 'auth.py')]:
        rel = os.path.relpath(p, ROOT)
        tree = ast.parse(open(p, encoding='utf-8').read())
        for top in tree.body:
            if not isinstance(top, ast.FunctionDef):
                continue
            # the sign-in routes: the browser never acts on a 401 of /api/auth/ by its URL;
            # the HA routes between instances sign their calls, no browser in between
            if any(r.startswith('/api/auth/') for r in _routes(top)):
                continue
            if rel == 'pegaprox/api/ha.py' and top.name != '_forward':
                continue
            for node in ast.walk(top):
                if not (isinstance(node, ast.Tuple) and len(node.elts) == 2
                        and isinstance(node.elts[1], ast.Constant) and node.elts[1].value == 401):
                    continue
                body = node.elts[0]
                d = body.args[0] if isinstance(body, ast.Call) and body.args else body
                code = None
                if isinstance(d, ast.Dict):
                    code = next((v.value for k, v in zip(d.keys, d.values)
                                 if isinstance(k, ast.Constant) and k.value == 'code'), None)
                seen.add(code)
                if code is None and (rel, top.name) in NOT_A_SESSION:
                    continue
                if code not in known:
                    bad.append(f'{rel}:{node.lineno} {top.name} code={code}')
    assert not bad, '\n'.join(bad)
    # counterproof that the walk sees what it should
    assert {'AUTH_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_DISABLED', 'INVALID_TOKEN', 'INVALID_SESSION',
            'HA_FORWARD_STALE_SIGN_IN'} <= seen
