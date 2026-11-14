"""A new container gets the root password its creator chose, an SSH key, or both - never a
fixed one.

create_container used to fill in a fixed root password whenever the request carried none,
an SSH key included, so a key-only container still got that password for root. Now the
manager sends a password only when a non-empty string was given; without one PVE sets
none. The LXC create route refuses a request with neither a password nor an SSH key, as
the PVE wizard does, and a password that is no string (JSON false would have become the
literal password 'False').

The route runs the real PegaProxManager.create_container and _api_post; only the HTTP
transport is replaced, so the tests read the form body that would go to PVE. The client
portal sends its own validated password and keeps doing so.
"""
import json
import types
from urllib.parse import parse_qs

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/nodes/n1/lxc'
TEMPLATE = 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst'
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0yTestKeyTestKeyTestKeyTestKeyTest0 ops@example'
CHOSEN = 'chosen-root-pw'


class _Transport(BaseAdapter):
    """Keeps every request PVE would have received and answers it with a task id."""

    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kw):
        self.sent.append(request)
        r = Response()
        r.status_code = 200
        r._content = json.dumps({'data': 'UPID:n1:0000:test'}).encode()
        r.headers['Content-Type'] = 'application/json'
        r.request, r.url = request, request.url
        return r

    def close(self):
        pass


def _pve(api, cluster_id=CID):
    """A manager whose create_container and _api_post are the real ones."""
    m = api.make_fake_manager(cluster_id=cluster_id)
    m.is_connected = True
    m.id = cluster_id
    m.host, m.api_port, m.api_timeout = '192.0.2.10', 8006, 5
    m.config.name = cluster_id
    m.get_pve_version_tuple.return_value = (9, 1)
    transport = _Transport()
    sess = requests.Session()
    sess.mount('https://', transport)
    m._create_session = lambda: sess
    m._api_post = types.MethodType(PegaProxManager._api_post, m)
    m.create_container = types.MethodType(PegaProxManager.create_container, m)
    api.set_manager(cluster_id, m)
    return m, transport


def _creates(transport):
    """The form bodies of the container creates that went out."""
    return [parse_qs(r.body or '', keep_blank_values=True) for r in transport.sent
            if r.method == 'POST' and r.url.endswith('/nodes/n1/lxc')]


def _callers(api, seed):
    seed.tenant('acme', clusters=[CID])
    op = seed.user('ctop', role='user', tenant_id='acme', permissions=['vm.create', 'cluster.view'])
    return {'operator': api.as_user(op), 'admin': api.as_user(seed.user('root', role='admin'))}


def _body(**extra):
    return dict({'vmid': 901, 'template': TEMPLATE, 'hostname': 'ct1'}, **extra)


# --- the route --------------------------------------------------------------------------------

NO_CREDENTIAL = {
    'nothing': {},
    'empty_password': {'password': ''},
    'null_password': {'password': None},
    'blank_key': {'ssh_public_keys': '  \n '},
    'both_empty': {'password': '', 'ssh_public_keys': '', 'ssh_key': ''},
}


@pytest.mark.parametrize('who', ['operator', 'admin'])
@pytest.mark.parametrize('case', list(NO_CREDENTIAL))
def test_a_container_with_neither_password_nor_key_is_refused(api, seed, who, case):
    _m, transport = _pve(api)
    r = _callers(api, seed)[who].post(URL, json=_body(**NO_CREDENTIAL[case]))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'root password or an SSH public key' in r.get_json()['error']
    assert transport.sent == []


@pytest.mark.parametrize('field', ['ssh_public_keys', 'ssh_key'])
@pytest.mark.parametrize('password', [None, '', 'absent'])
def test_a_key_only_container_gets_no_root_password(api, seed, field, password):
    _m, transport = _pve(api)
    extra = {field: KEY}
    if password != 'absent':
        extra['password'] = password
    r = _callers(api, seed)['operator'].post(URL, json=_body(**extra))
    assert r.status_code == 200, r.get_data(as_text=True)
    [sent] = _creates(transport)
    assert sent['ssh-public-keys'] == [KEY]
    assert 'password' not in sent, sorted(sent)


@pytest.mark.parametrize('extra', [{}, {'ssh_public_keys': KEY}])
def test_the_chosen_password_reaches_pve_as_given(api, seed, extra):
    _m, transport = _pve(api)
    r = _callers(api, seed)['admin'].post(URL, json=_body(password=CHOSEN, **extra))
    assert r.status_code == 200, r.get_data(as_text=True)
    [sent] = _creates(transport)
    assert sent['password'] == [CHOSEN]


@pytest.mark.parametrize('password', [False, True, 0, 123456, ['a' * 8], {'pw': 'x' * 8}])
def test_a_password_that_is_no_string_is_refused(api, seed, password):
    _m, transport = _pve(api)
    r = _callers(api, seed)['admin'].post(URL, json=_body(password=password, ssh_public_keys=KEY))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'string' in r.get_json()['error']
    assert transport.sent == []


def test_a_body_that_is_no_object_is_a_clean_refusal(api, seed):
    _m, transport = _pve(api)
    r = _callers(api, seed)['admin'].post(URL, json=[TEMPLATE, KEY])
    assert r.status_code == 400, r.get_data(as_text=True)
    assert transport.sent == []


def test_an_api_token_with_a_key_creates_a_key_only_container(api, seed):
    from pegaprox.utils.auth import create_api_token
    _m, transport = _pve(api)
    seed.user('root', role='admin')
    tok = create_api_token('root', 'automation')
    assert 'token' in tok, sorted(tok)
    headers = {'Authorization': f"Bearer {tok['token']}"}
    r = api.anon().post(URL, headers=headers, json=_body(ssh_public_keys=KEY))
    assert r.status_code == 200, r.get_data(as_text=True)
    [sent] = _creates(transport)
    assert 'password' not in sent and sent['ssh-public-keys'] == [KEY]
    r = api.anon().post(URL, headers=headers, json=_body(vmid=902))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert len(_creates(transport)) == 1


# --- the manager, for every caller --------------------------------------------------------------

@pytest.mark.parametrize('config', [{}, {'password': ''}, {'password': None}, {'ssh_key': KEY}],
                         ids=['absent', 'empty', 'null', 'key_only'])
def test_the_manager_sends_no_password_it_was_not_given(api, config):
    m, transport = _pve(api)
    res = m.create_container('n1', dict({'vmid': 903, 'template': TEMPLATE}, **config))
    assert res.get('success') is True, res
    [sent] = _creates(transport)
    assert 'password' not in sent, sorted(sent)


@pytest.mark.parametrize('password', [False, 0, ['a' * 8]])
def test_the_manager_refuses_a_password_that_is_no_string(api, password):
    m, transport = _pve(api)
    res = m.create_container('n1', {'vmid': 904, 'template': TEMPLATE, 'password': password})
    assert res.get('success') is False and 'string' in res.get('error', ''), res
    assert transport.sent == []


# --- the client portal keeps its own password -------------------------------------------------

def test_the_portal_password_reaches_pve(api, seed, monkeypatch):
    import plugins.client_portal as portal
    from flask import request as _rq
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '192.0.2.10', 'root@pam', 'x')''', ('cluster_p', 'cluster_p'))
    seed.tenant('t_cust', ['cluster_p'])
    seed.user('cust', role='user', tenant_id='t_cust')
    _m, transport = _pve(api, 'cluster_p')
    import pegaprox.utils.rbac as rbac
    monkeypatch.setattr(rbac, 'tenants_db', {}, raising=False)
    monkeypatch.setattr(portal, '_load_config', lambda: {
        'allow_ct_create': True,
        'ct_create': {'cluster_id': 'cluster_p', 'node': 'n1', 'templates': [TEMPLATE],
                      'max_cores': 2, 'max_memory_mb': 2048, 'max_disk_gb': 16}})
    form = {'template': TEMPLATE, 'cores': 1, 'memory': 512, 'disk_gb': 8,
            'hostname': 'web01', 'password': 'portal-chosen-pw'}
    with api.app.test_request_context('/', base_url='http://localhost', json=form):
        _rq.session = {'user': 'cust', 'role': 'user'}
        res = portal._create_ct()
    assert not isinstance(res, tuple) and res.get('success') is True, res
    [sent] = _creates(transport)
    assert sent['password'] == ['portal-chosen-pw']


# --- the credential goes to PVE as given, or the request is refused ------------------------------

@pytest.mark.parametrize('password', ['\x00' * 5, 'ab\x00cdefgh', CHOSEN + '\x00'],
                         ids=['only_nul', 'nul_inside', 'nul_at_end'])
def test_a_password_with_a_nul_is_refused(api, seed, password):
    """PVE hashes the password with crypt(), which ends it at the first NUL, so root would
    get another password than the one in the request."""
    _m, transport = _pve(api)
    r = _callers(api, seed)['admin'].post(URL, json=_body(password=password, ssh_public_keys=KEY))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'NUL' in r.get_json()['error']
    assert transport.sent == []


def test_the_manager_refuses_a_password_with_a_nul(api):
    m, transport = _pve(api)
    res = m.create_container('n1', {'vmid': 905, 'template': TEMPLATE, 'password': 'ab\x00cdefgh'})
    assert res.get('success') is False and 'NUL' in res.get('error', ''), res
    assert transport.sent == []


@pytest.mark.parametrize('blank', ['   ', ' \n\t '], ids=['spaces', 'mixed'])
def test_a_blank_key_field_does_not_hide_the_key_in_the_alias(api, seed, blank):
    _m, transport = _pve(api)
    caller = _callers(api, seed)['operator']
    r = caller.post(URL, json=_body(ssh_public_keys=blank, ssh_key=KEY))
    assert r.status_code == 200, r.get_data(as_text=True)
    r = caller.post(URL, json=_body(vmid=902, ssh_public_keys=blank, ssh_key=KEY, password=CHOSEN))
    assert r.status_code == 200, r.get_data(as_text=True)
    key_only, both = _creates(transport)
    assert key_only['ssh-public-keys'] == [KEY] and 'password' not in key_only, key_only
    assert both['ssh-public-keys'] == [KEY] and both['password'] == [CHOSEN], both


def test_the_manager_takes_the_key_from_the_alias_behind_a_blank_field(api):
    m, transport = _pve(api)
    res = m.create_container('n1', {'vmid': 906, 'template': TEMPLATE,
                                    'ssh_public_keys': '  \n', 'ssh_key': KEY})
    assert res.get('success') is True, res
    [sent] = _creates(transport)
    assert sent['ssh-public-keys'] == [KEY]


@pytest.mark.parametrize('field', ['ssh_public_keys', 'ssh_key'])
@pytest.mark.parametrize('keys', [[KEY], {'k': KEY}, 1, True], ids=['list', 'dict', 'number', 'true'])
def test_a_key_field_that_is_no_string_is_refused(api, seed, field, keys):
    """Next to a password too, where the key would otherwise go missing or arrive mangled."""
    _m, transport = _pve(api)
    r = _callers(api, seed)['admin'].post(URL, json=_body(password=CHOSEN, **{field: keys}))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'string' in r.get_json()['error']
    assert transport.sent == []


@pytest.mark.parametrize('cluster_type,extra', [('xcpng', {}), ('esxi', {}), ('esxi', {'password': CHOSEN})],
                         ids=['xcpng', 'esxi', 'esxi_with_password'])
def test_a_cluster_without_containers_says_so_first(api, seed, cluster_type, extra):
    m = api.make_fake_manager(cluster_id=CID, cluster_type=cluster_type)
    if cluster_type == 'xcpng':
        m.create_container.return_value = {'success': False, 'error': 'LXC containers not supported on XCP-ng'}
    else:
        del m.create_container          # the ESXi wrapper has none
    api.set_manager(CID, m)
    r = _callers(api, seed)['admin'].post(URL, json=_body(**extra))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'Proxmox' in r.get_json()['error']
    if cluster_type == 'xcpng':
        assert not m.create_container.called


# --- the client portal refuses what it cannot send as given ------------------------------------

PORTAL_FORM = {'template': TEMPLATE, 'cores': 1, 'memory': 512, 'disk_gb': 8, 'hostname': 'web01'}


def _portal_create(api, seed, monkeypatch, body):
    import plugins.client_portal as portal
    from flask import request as _rq
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '192.0.2.10', 'root@pam', 'x')''', ('cluster_p', 'cluster_p'))
    seed.tenant('t_cust', ['cluster_p'])
    seed.user('cust', role='user', tenant_id='t_cust')
    _m, transport = _pve(api, 'cluster_p')
    import pegaprox.utils.rbac as rbac
    monkeypatch.setattr(rbac, 'tenants_db', {}, raising=False)
    monkeypatch.setattr(portal, '_load_config', lambda: {
        'allow_ct_create': True,
        'ct_create': {'cluster_id': 'cluster_p', 'node': 'n1', 'templates': [TEMPLATE],
                      'max_cores': 2, 'max_memory_mb': 2048, 'max_disk_gb': 16}})
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = {'user': 'cust', 'role': 'user'}
        return portal._create_ct(), transport


@pytest.mark.parametrize('password', [12345678, 1234567.5, ['a'] * 8, {str(i): i for i in range(8)},
                                      'portal\x00chosen'],
                         ids=['int', 'float', 'list', 'dict', 'nul'])
def test_the_portal_refuses_a_password_it_cannot_send_as_given(api, seed, monkeypatch, password):
    res, transport = _portal_create(api, seed, monkeypatch, dict(PORTAL_FORM, password=password))
    assert isinstance(res, tuple) and res[1] == 400, res
    assert transport.sent == []


def test_the_portal_refuses_a_body_that_is_no_object(api, seed, monkeypatch):
    res, transport = _portal_create(api, seed, monkeypatch, [dict(PORTAL_FORM, password='portal-chosen-pw')])
    assert isinstance(res, tuple) and res[1] == 400, res
    assert transport.sent == []
