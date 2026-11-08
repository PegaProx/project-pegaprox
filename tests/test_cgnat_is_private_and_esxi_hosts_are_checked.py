"""Two rules for the hosts PegaProx reaches out to.

The shared address space 100.64.0.0/10 (carrier-grade NAT, tailnets) is as internal as
RFC1918, but the stdlib calls it neither private nor reserved, so the outbound guard let
it through wherever it refused 10.x and 192.168.x. Any signed-in user could hand such an
address to the ISO download, which the Proxmox node then fetched and stored as a readable
image. It now counts as private: refused where private ranges are, allowed where they
are opted in, also when it hides in a v4-mapped, 6to4 or NAT64 address or behind a name.

An ESXi server's host went straight into a connection from add, update and the
connection test. A vmware.config holder could point it at the cloud metadata address or
at a port on this server's loopback, and the error told whether anything listened. The
PBS routes refuse those since the last round; ESXi now shares that rule. The LAN stays
open (an ESXi host lives there), link-local never, loopback only for a global admin.
MK Oct 2026
"""
import socket
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.url_security as url_security
from pegaprox.core.vmware import VMwareManager, save_vmware_server
from pegaprox.utils.url_security import SsrfError, is_safe_outbound_url, resolve_and_pin_url


SHARED = ['100.64.0.1', '100.127.255.254', '::ffff:100.64.0.1',
          '2002:6440:1::1',        # 6to4 around 100.64.0.1
          '64:ff9b::6440:1']       # NAT64 around 100.64.0.1


def _url(ip, scheme='https'):
    return f'{scheme}://[{ip}]/x.iso' if ':' in ip else f'{scheme}://{ip}/x.iso'


def _resolves_to(monkeypatch, ip):
    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
    monkeypatch.setattr(url_security.socket, 'getaddrinfo',
                        lambda *a, **kw: [(fam, socket.SOCK_STREAM, 6, '', (ip, 0))])


# -- the shared address space ---------------------------------------------------------------------

@pytest.mark.parametrize('ip', SHARED)
def test_the_shared_address_space_is_refused_where_private_ranges_are(ip):
    ok, why = is_safe_outbound_url(_url(ip), allow_private=False)
    assert ok is False, (ip, why)
    with pytest.raises(SsrfError):
        resolve_and_pin_url(_url(ip, 'http'), allowed_schemes=('http', 'https'), tls_verified=False)


@pytest.mark.parametrize('ip', SHARED + ['10.0.0.1'])
def test_it_is_allowed_where_private_ranges_are_opted_in(ip):
    # the LAN call sites keep working for a tailnet target, the same way they do for 10.x
    ok, why = is_safe_outbound_url(_url(ip), allow_private=True, allow_loopback=False)
    assert ok is True, (ip, why)


@pytest.mark.parametrize('ip', ['100.63.255.255', '100.128.0.0', '1.1.1.1'])
def test_the_addresses_around_it_stay_public(ip):
    ok, why = is_safe_outbound_url(_url(ip), allow_private=False)
    assert ok is True, (ip, why)


def test_a_name_that_resolves_into_it_is_refused(monkeypatch):
    _resolves_to(monkeypatch, '100.101.102.103')
    ok, why = is_safe_outbound_url('https://box.tailnet.example/x', allow_private=False)
    assert ok is False and '100.101.102.103' in why
    with pytest.raises(SsrfError):
        resolve_and_pin_url('http://box.tailnet.example/x', allowed_schemes=('http', 'https'))
    assert is_safe_outbound_url('https://box.tailnet.example/x', allow_private=True)[0] is True
    # a name with a public address is still pinned and passed
    _resolves_to(monkeypatch, '1.1.1.1')
    assert resolve_and_pin_url('http://box.example/x', allowed_schemes=('http', 'https')) == 'http://1.1.1.1/x'


def _download(api, seed, url):
    mgr = api.make_fake_manager('cl_dl')
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'pve.example', 8006
    resp = MagicMock(status_code=500, text='stub')
    sess = MagicMock()
    sess.post.return_value = resp
    mgr._create_session.return_value = sess
    api.set_manager('cl_dl', mgr)
    u = api.as_user(seed.user('uploader', role='user'))   # default tenant, holds storage.upload
    r = u.post('/api/clusters/cl_dl/datastores/local/download-url', json={'url': url, 'node': 'pve1'})
    return r, sess


def test_the_iso_download_does_not_hand_the_range_to_the_node(api, seed):
    r, sess = _download(api, seed, 'http://100.64.0.1/x.iso')
    assert r.status_code == 400 and 'SSRF' in r.get_json()['error'], r.get_json()
    assert not sess.post.called


def test_the_iso_download_still_hands_a_public_url_to_the_node(api, seed):
    r, sess = _download(api, seed, 'http://1.1.1.1/x.iso')
    assert sess.post.called, r.get_json()
    assert sess.post.call_args.kwargs['data']['url'] == 'http://1.1.1.1/x.iso'


def test_a_push_subscription_cannot_point_into_the_range(api, seed):
    u = api.as_user(seed.user('pusher', role='user'))

    def sub(ep):
        return u.post('/api/push/subscribe', json={'endpoint': ep, 'keys': {'p256dh': 'x', 'auth': 'y'}})
    assert sub('https://100.64.0.9/push/abc').status_code == 400
    assert sub('https://1.1.1.1/push/abc').status_code == 200


# -- the ESXi hosts PegaProx dials ----------------------------------------------------------------

@pytest.mark.parametrize('host,admin,refused', [
    ('10.0.0.5', False, ''),
    ('192.168.10.20', False, ''),
    ('100.64.0.7', False, ''),              # a tailnet ESXi is LAN like RFC1918
    ('[fd12:3456::5]', False, ''),
    ('127.0.0.1', False, 'loopback'),
    ('localhost', False, 'loopback'),
    ('[::1]', False, 'loopback'),
    ('0.0.0.0', False, 'loopback'),
    ('[::ffff:127.0.0.1]', False, 'loopback'),
    ('127.0.0.1', True, ''),
    ('localhost', True, ''),
    ('169.254.169.254', True, 'link-local'),
    ('2852039166', True, 'link-local'),     # 169.254.169.254 as one number
    ('[::ffff:169.254.169.254]', True, 'link-local'),
    ('[2002:a9fe:a9fe::1]', True, 'link-local'),
    ('fe80::1', True, 'link-local'),
    ('[fd00:ec2::254]', True, 'metadata'),
    # the host goes into https://{host}:{port}/ as is, these would dial somebody else
    ('169.254.169.254/x', True, 'Invalid'),
    ('user@169.254.169.254', True, 'Invalid'),
    ('169.254.169.254#', True, 'Invalid'),
    ('169.254.169.254:80', True, 'Invalid'),
    ('https://10.0.0.5', True, 'Invalid'),
    ('[esxi.lab]', True, 'Invalid'),
    ('', True, 'Invalid'),
    (None, True, 'Invalid'),
    (5, True, 'Invalid'),
])
def test_which_esxi_hosts_are_dialled(host, admin, refused):
    from pegaprox.core.vmware import esxi_target_refusal
    why = esxi_target_refusal(host, allow_loopback=admin)
    if refused:
        assert refused in why, (host, why)
    else:
        assert why == '', (host, why)


def test_a_name_that_does_not_resolve_is_left_to_the_connection(monkeypatch):
    def nope(*a, **kw):
        raise socket.gaierror('no such name')
    monkeypatch.setattr(url_security.socket, 'getaddrinfo', nope)
    from pegaprox.core.vmware import esxi_target_refusal
    assert esxi_target_refusal('esxi-01.lab.internal', allow_loopback=False) == ''


@pytest.fixture
def dialled(monkeypatch):
    calls = []

    def connect(self):
        calls.append((self.host, self.port))
        self.last_error = 'stub refused'
        return False
    monkeypatch.setattr(VMwareManager, 'connect', connect)
    return calls


@pytest.fixture
def esx_users(api, seed):
    return {
        'admin': api.as_user(seed.user('root_adm', role='admin')),
        # the ESXi config right on a non-admin (a custom role or an extra grant)
        'ops': api.as_user(seed.user('esx_ops', role='user', permissions=['vmware.config'])),
    }


_CREDS = {'username': 'root', 'password': 'pw'}


@pytest.mark.parametrize('path', ['/api/vmware/test-connection', '/api/vmware'])
def test_add_and_the_connection_test_refuse_before_they_dial(path, esx_users, dialled):
    for host, port, word in [('169.254.169.254', 80, 'link-local'),
                             ('127.0.0.1', 5000, 'loopback'),
                             ('localhost', 5000, 'loopback'),
                             ('169.254.169.254/x', 443, 'Invalid')]:
        r = esx_users['ops'].post(path, json=dict(_CREDS, name='esx', host=host, port=port))
        assert r.status_code == 400 and word in r.get_json()['error'], (host, r.get_json())
    r = esx_users['admin'].post(path, json=dict(_CREDS, name='esx', host='169.254.169.254'))
    assert r.status_code == 400 and 'link-local' in r.get_json()['error']
    assert dialled == []


@pytest.mark.parametrize('path', ['/api/vmware/test-connection', '/api/vmware'])
def test_add_and_the_connection_test_still_reach_the_lan_and_an_admin_the_loopback(path, esx_users, dialled):
    r = esx_users['ops'].post(path, json=dict(_CREDS, name='esx', host='10.0.0.5', port=443))
    assert r.status_code == 400 and 'stub refused' in r.get_json()['error'], r.get_json()
    r = esx_users['admin'].post(path, json=dict(_CREDS, name='esx', host='127.0.0.1', port=8443))
    assert 'stub refused' in r.get_json()['error'], r.get_json()
    assert dialled == [('10.0.0.5', 443), ('127.0.0.1', 8443)]


def _stored(sid, host, port=443):
    save_vmware_server(sid, {'name': sid, 'host': host, 'port': port, 'username': 'root',
                             'password': 'stored-pw', 'linked_clusters': []})
    ppglobals.vmware_managers[sid] = VMwareManager(sid, {'name': sid, 'host': host, 'port': port,
                                                         'username': 'root', 'password': 'stored-pw'})


def _form(sid, host, port=443, **kw):
    # the edit dialog sends the whole form; a typed password, as a host change requires
    return dict({'name': sid, 'host': host, 'port': port, 'username': 'root', 'password': 'pw'}, **kw)


def _row(sid):
    from pegaprox.core.db import get_db
    r = get_db().conn.cursor().execute('SELECT host, port FROM vmware_servers WHERE id = ?', (sid,)).fetchone()
    return r['host'], int(r['port'])


def test_moving_a_server_to_a_refused_host_is_refused(esx_users, dialled):
    _stored('esx1', '10.0.0.5')
    r = esx_users['admin'].put('/api/vmware/esx1', json=_form('esx1', '169.254.169.254'))
    assert r.status_code == 400 and 'link-local' in r.get_json()['error'], r.get_json()
    r = esx_users['ops'].put('/api/vmware/esx1', json=_form('esx1', '127.0.0.1'))
    assert r.status_code == 400 and 'loopback' in r.get_json()['error'], r.get_json()
    assert _row('esx1') == ('10.0.0.5', 443)
    assert dialled == []


def test_a_new_port_on_a_loopback_host_is_a_new_target(esx_users, dialled):
    # an admin's ESXi behind an SSH forward on this server; a delegate may not walk its ports
    _stored('esx2', '127.0.0.1', 8443)
    r = esx_users['ops'].put('/api/vmware/esx2', json=_form('esx2', '127.0.0.1', 5000))
    assert r.status_code == 400 and 'loopback' in r.get_json()['error'], r.get_json()
    r = esx_users['ops'].put('/api/vmware/esx2', json={'port': 5000, 'password': 'pw'})
    assert r.status_code == 400 and 'loopback' in r.get_json()['error'], r.get_json()
    assert _row('esx2') == ('127.0.0.1', 8443)
    assert dialled == []
    # leaving the target alone is fine, and so is the admin moving it
    r = esx_users['ops'].put('/api/vmware/esx2', json=_form('esx2', '127.0.0.1', 8443, notes='rack 2'))
    assert r.status_code == 200, r.get_json()
    r = esx_users['admin'].put('/api/vmware/esx2', json=_form('esx2', '127.0.0.1', 9443))
    assert r.status_code == 200, r.get_json()
    assert _row('esx2') == ('127.0.0.1', 9443)
    assert dialled == [('127.0.0.1', 8443), ('127.0.0.1', 9443)]


def test_moving_a_server_within_the_lan_still_works(esx_users, dialled):
    _stored('esx3', '10.0.0.5')
    r = esx_users['ops'].put('/api/vmware/esx3', json=_form('esx3', '10.0.0.6'))
    assert r.status_code == 200, r.get_json()
    assert _row('esx3') == ('10.0.0.6', 443)
    assert dialled == [('10.0.0.6', 443)]
