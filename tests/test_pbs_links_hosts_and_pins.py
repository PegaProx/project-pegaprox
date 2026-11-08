"""A PBS server's links, the hosts PegaProx dials for it, and the certificate it trusts.

- Adding a server (#995). The update has refused an empty or foreign linked_clusters list
  from a non-admin since September; the add had no such check, so a pbs.config holder
  could create a server linked to nothing, which check_pbs_access opens to every tenant,
  or to clusters they do not reach.
- auto-storage (#980) took any target cluster the caller's tenant owns. Reaching the server
  through one linked cluster was enough to plant its stored credentials on another one.
- The certificate (#1074). auto-storage read the live certificate unverified and told PVE to
  trust it, past the fingerprint the server is pinned to; storage-preflight noted a
  fingerprint mismatch and then posted the typed password to that server anyway.
- The hosts. The PBS host check was format-only: the loopback of this server and the
  link-local range (where the cloud metadata services answer) were dialled, and the error
  told whether anything listened. Private ranges stay open, a PBS lives on the LAN; loopback
  stays open to a global admin, who may run PegaProx on the PBS host itself.
NS Oct 2026
"""
import hashlib
import socket
import ssl
from unittest.mock import MagicMock

import pytest
import requests

import pegaprox.api.pbs as pbs_api
import pegaprox.globals as ppglobals
from pegaprox.core.pbs import _PinnedFingerprintAdapter

CERT = b'the certificate the PBS presents'
OTHER = b'a certificate somebody else presents'


def _colons(der):
    h = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(h[i:i + 2] for i in range(0, len(h), 2))


class _Recorder:
    """PBSManager in the routes: records what it was built for, never connects."""
    built = []

    def __init__(self, pbs_id, config):
        type(self).built.append(dict(config))
        self.last_error = 'Connection failed'
        self.linked_clusters = config.get('linked_clusters', [])

    def connect(self):
        return False


@pytest.fixture
def recorder(monkeypatch):
    _Recorder.built = []
    monkeypatch.setattr(pbs_api, 'PBSManager', _Recorder)
    return _Recorder


@pytest.fixture
def clean_pbs():
    ppglobals.pbs_managers.clear()
    yield ppglobals.pbs_managers
    ppglobals.pbs_managers.clear()


@pytest.fixture
def users(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1', 'cluster_2'])
    seed.tenant('tenant_b', clusters=['cluster_9'])
    return {
        'admin': api.as_user(seed.user('root_adm', role='admin')),
        # a tenant delegate with the PBS config right (a custom role or an extra grant)
        'tenant': api.as_user(seed.user('a_ops', role='user', tenant_id='tenant_a',
                                        permissions=['pbs.config', 'storage.config'])),
        # the same right in the default tenant: every cluster, but no admin
        'unconfined': api.as_user(seed.user('ops', role='user', permissions=['pbs.config'])),
    }


_ADD = {'name': 'pbs', 'host': '10.0.0.5', 'user': 'root@pam', 'password': 'pw'}


# -- adding a server (#995) ---------------------------------------------------------------------

def test_a_delegate_cannot_add_a_server_linked_to_nothing(users, recorder, clean_pbs):
    r = users['tenant'].post('/api/pbs', json=dict(_ADD, linked_clusters=[]))
    assert r.status_code == 403, r.get_json()
    assert recorder.built == []
    r = users['tenant'].post('/api/pbs', json=dict(_ADD))   # leaving the list out is the same
    assert r.status_code == 403
    assert recorder.built == []


def test_a_delegate_cannot_link_a_new_server_to_a_foreign_cluster(users, recorder, clean_pbs):
    r = users['tenant'].post('/api/pbs', json=dict(_ADD, linked_clusters=['cluster_1', 'cluster_9']))
    assert r.status_code == 403
    assert 'cluster_9' in r.get_json()['error']
    assert recorder.built == []


def test_a_delegate_adds_a_server_linked_to_their_own_clusters(users, recorder, clean_pbs):
    r = users['tenant'].post('/api/pbs', json=dict(_ADD, linked_clusters=['cluster_2']))
    assert r.status_code == 400 and 'Connection failed' in r.get_json()['error']   # got to the connection
    assert recorder.built[0]['linked_clusters'] == ['cluster_2']


def test_an_unconfined_operator_still_needs_a_link_but_may_pick_any(users, recorder, clean_pbs):
    assert users['unconfined'].post('/api/pbs', json=_ADD).status_code == 403
    r = users['unconfined'].post('/api/pbs', json=dict(_ADD, linked_clusters=['cluster_9']))
    assert r.status_code == 400 and recorder.built


def test_an_admin_adds_a_server_for_everybody(users, recorder, clean_pbs):
    r = users['admin'].post('/api/pbs', json=dict(_ADD, linked_clusters=[]))
    assert r.status_code == 400 and recorder.built   # past every check, at the connection


def test_the_update_keeps_its_rule(users, recorder, clean_pbs):
    m = MagicMock(host='10.0.0.5', port=8007, linked_clusters=['cluster_1'], password='', api_token_secret='',
                  ssh_key='')
    clean_pbs['p1'] = m
    r = users['tenant'].put('/api/pbs/p1', json={'linked_clusters': []})
    assert r.status_code == 403 and 'unlink' in r.get_json()['error']
    r = users['tenant'].put('/api/pbs/p1', json={'linked_clusters': ['cluster_9']})
    assert r.status_code == 403 and 'cluster_9' in r.get_json()['error']
    assert recorder.built == []


# -- auto-storage targets (#980) ----------------------------------------------------------------

@pytest.fixture
def tls(monkeypatch):
    """The TLS peer the probes meet: set .der to what it presents."""
    class _Tls:
        der = CERT

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getpeercert(self, binary_form=False):
            return type(self).der

    class _Ctx:
        def wrap_socket(self, sock, server_hostname=None):
            return _Tls()

    monkeypatch.setattr(socket, 'create_connection', lambda *a, **kw: _Tls())
    monkeypatch.setattr(ssl, '_create_unverified_context', lambda: _Ctx())
    return _Tls


def _stored_pbs(linked, fingerprint=''):
    m = MagicMock(linked_clusters=linked, host='10.0.0.5', port=8007, user='root@pam', password='stored-pw',
                  fingerprint=fingerprint)
    m.name = 'pbs1'
    m.get_datastores.return_value = {'data': [{'store': 'ds1'}]}
    return m


def _cluster(api, cid):
    cm = api.make_fake_manager(cid)
    cm.is_connected = True
    cm.host, cm.api_port = '10.0.1.1', 8006
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=200)
    cm._create_session.return_value = session
    api.set_manager(cid, cm)
    return session


def test_auto_storage_puts_the_credentials_only_where_the_server_is_linked(api, users, clean_pbs, tls):
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'])
    pve = _cluster(api, 'cluster_2')
    r = users['tenant'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_2']})
    assert r.status_code == 403, r.get_json()
    assert 'not linked' in r.get_json()['error'] and 'cluster_2' in r.get_json()['error']
    assert not pve.post.called


def test_auto_storage_on_a_linked_cluster_works_for_the_delegate(api, users, clean_pbs, tls):
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'])
    pve = _cluster(api, 'cluster_1')
    r = users['tenant'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_1']})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['results'][0]['ok'] is True
    assert pve.post.call_args.kwargs['data']['password'] == 'stored-pw'


def test_an_admin_attaches_a_server_anywhere(api, users, clean_pbs, tls):
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'])
    pve = _cluster(api, 'cluster_2')
    r = users['admin'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_2']})
    assert r.status_code == 200 and pve.post.called


# -- the certificate PVE is told to trust (#1074) ----------------------------------------------

def test_auto_storage_refuses_a_certificate_that_is_not_the_pinned_one(api, users, clean_pbs, tls):
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'], fingerprint=_colons(CERT))
    pve = _cluster(api, 'cluster_1')
    tls.der = OTHER
    r = users['admin'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_1']})
    assert r.status_code == 502, r.get_json()
    assert 'stored fingerprint' in r.get_json()['error']
    assert not pve.post.called, 'the credentials went out with a foreign certificate'


def test_auto_storage_hands_pve_the_pinned_fingerprint(api, users, clean_pbs, tls):
    # written the way an operator might paste it: lower case, no colons
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'], fingerprint=hashlib.sha256(CERT).hexdigest())
    pve = _cluster(api, 'cluster_1')
    r = users['admin'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_1']})
    assert r.status_code == 200, r.get_json()
    assert pve.post.call_args.kwargs['data']['fingerprint'] == _colons(CERT)


def test_auto_storage_without_a_pin_takes_the_probe_as_before(api, users, clean_pbs, tls):
    clean_pbs['pbs1'] = _stored_pbs(['cluster_1'])
    pve = _cluster(api, 'cluster_1')
    tls.der = OTHER
    r = users['admin'].post('/api/pbs/pbs1/auto-storage', json={'clusters': ['cluster_1']})
    assert r.status_code == 200
    assert pve.post.call_args.kwargs['data']['fingerprint'] == _colons(OTHER)


@pytest.fixture
def logins(monkeypatch):
    """Every login the preflight sends: (session, url, form)."""
    sent = []

    def post(self, url, data=None, **kw):
        sent.append((self, url, dict(data or {})))
        return MagicMock(status_code=401)
    monkeypatch.setattr(requests.Session, 'post', post)
    return sent


def _preflight(client, **body):
    return client.post('/api/clusters/cluster_1/storage-preflight', json=dict(
        {'type': 'pbs', 'server': '10.0.0.5', 'port': 8007, 'datastore': 'ds1', 'username': 'root@pam',
         'password': 'typed-pw'}, **body))


def test_the_preflight_keeps_the_password_when_the_fingerprint_does_not_match(api, users, tls, logins):
    _cluster(api, 'cluster_1')
    tls.der = OTHER
    r = _preflight(users['admin'], fingerprint=_colons(CERT))
    j = r.get_json()
    assert j['ok'] is False and any('mismatch' in i for i in j['issues']), j
    assert logins == [], 'the typed password went to a server with another certificate'


def test_the_preflight_logs_in_only_to_the_certificate_it_was_given(api, users, tls, logins):
    _cluster(api, 'cluster_1')
    r = _preflight(users['admin'], fingerprint=hashlib.sha256(CERT).hexdigest())   # no colons, lower case
    j = r.get_json()
    assert not any('mismatch' in i for i in j['issues']), j
    (session, url, form), = logins
    assert url.endswith('/access/ticket') and form['password'] == 'typed-pw'
    assert isinstance(session.get_adapter(url), _PinnedFingerprintAdapter)


def test_the_preflight_without_a_fingerprint_is_unchanged(api, users, tls, logins):
    _cluster(api, 'cluster_1')
    r = _preflight(users['admin'])
    assert r.get_json()['info']['live_fingerprint'] == _colons(CERT)
    assert len(logins) == 1


# -- the hosts PegaProx dials --------------------------------------------------------------------

@pytest.mark.parametrize('host,admin,refused', [
    ('10.0.0.5', False, ''),
    ('192.168.10.20', False, ''),
    ('127.0.0.1', False, 'loopback'),
    ('127.8.9.10', False, 'loopback'),
    ('::1', False, 'loopback'),
    ('0.0.0.0', False, 'loopback'),
    ('::ffff:127.0.0.1', False, 'loopback'),
    ('localhost', False, 'loopback'),
    ('127.0.0.1', True, ''),
    ('localhost', True, ''),
    ('169.254.169.254', True, 'link-local'),
    ('169.254.10.20', True, 'link-local'),
    ('::ffff:169.254.169.254', True, 'link-local'),
    ('2002:a9fe:a9fe::1', True, 'link-local'),
    ('fe80::1', True, 'link-local'),
    ('fd00:ec2::254', True, 'metadata'),
    ('http://10.0.0.5/', True, 'Invalid'),
])
def test_which_hosts_are_dialled(host, admin, refused):
    from pegaprox.core.pbs import pbs_target_refusal
    why = pbs_target_refusal(host, allow_loopback=admin)
    if refused:
        assert refused in why, (host, why)
    else:
        assert why == '', (host, why)


def test_a_name_that_does_not_resolve_is_left_to_the_connection(monkeypatch):
    def nope(*a, **kw):
        raise socket.gaierror('no such name')
    monkeypatch.setattr(socket, 'getaddrinfo', nope)
    from pegaprox.core.pbs import pbs_target_refusal
    assert pbs_target_refusal('pbs.internal', allow_loopback=False) == ''


@pytest.mark.parametrize('path', ['/api/pbs/test-connection', '/api/pbs/p1/test'])
def test_the_connection_test_dials_no_loopback_for_a_delegate(path, users, recorder, clean_pbs):
    for host in ('127.0.0.1', 'localhost', '169.254.169.254'):
        r = users['unconfined'].post(path, json={'host': host, 'port': 22, 'user': 'root@pam', 'password': 'x'})
        assert r.status_code == 400, (host, r.get_json())
        assert 'loopback' in r.get_json()['error'] or 'link-local' in r.get_json()['error']
    assert recorder.built == []


def test_the_connection_test_still_reaches_the_lan_and_an_admin_the_loopback(users, recorder, clean_pbs):
    r = users['unconfined'].post('/api/pbs/test-connection', json={'host': '10.0.0.5', 'user': 'root@pam',
                                                                  'password': 'x'})
    assert r.status_code == 400 and len(recorder.built) == 1   # tried, and the stand-in refused
    r = users['admin'].post('/api/pbs/test-connection', json={'host': '127.0.0.1', 'user': 'root@pam',
                                                             'password': 'x'})
    assert len(recorder.built) == 2


def test_adding_or_moving_a_server_to_a_refused_host(users, recorder, clean_pbs):
    r = users['admin'].post('/api/pbs', json=dict(_ADD, host='169.254.169.254', linked_clusters=['cluster_1']))
    assert r.status_code == 400 and 'link-local' in r.get_json()['error']
    clean_pbs['p1'] = MagicMock(host='10.0.0.5', port=8007, linked_clusters=[], password='', api_token_secret='',
                                ssh_key='')
    r = users['unconfined'].put('/api/pbs/p1', json={'host': '127.0.0.1'})
    assert r.status_code == 400 and 'loopback' in r.get_json()['error']
    assert recorder.built == []


def test_the_fingerprint_probe_and_the_preflight_refuse_the_same_hosts(api, users, tls, logins):
    _cluster(api, 'cluster_1')
    r = users['admin'].post('/api/pbs/probe-fingerprint', json={'host': '169.254.170.2', 'port': 80})
    assert r.status_code == 400 and 'link-local' in r.get_json()['error']
    r = _preflight(users['admin'], server='169.254.170.2')
    assert r.get_json()['ok'] is False and 'link-local' in r.get_json()['issues'][0]
    assert logins == []
