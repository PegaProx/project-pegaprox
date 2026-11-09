"""Per-node address and port overrides.

A cluster is normally reached at one host and one SSH/API port, and every node at the
address it reports for itself. Behind a per-node port forward -- five nodes on one
public address, 2201..2205 and 8006..8010 -- neither holds: the addresses the nodes
report are the ones PegaProx cannot reach, and one ssh_port cannot name five listeners.

`node_endpoints` is {node: {host?, ssh_port?, api_port?}}. An entry wins over discovery
for that node and over the cluster's ports. It also moves the cluster's credential, so
it is covered by the same re-entry rule as host, fallback_hosts and ssh_port.
"""
import threading
import types

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig, normalize_node_endpoints


HOST = '10.40.0.1'
PUBLIC = '203.0.113.9'
STORED_PW = 'stored-cluster-password'

NAT = {
    'node01': {'host': PUBLIC, 'ssh_port': 2201, 'api_port': 8006},
    'node02': {'host': PUBLIC, 'ssh_port': 2202, 'api_port': 8007},
}


def _row(**over):
    row = dict(name='lab', host=HOST, user='root@pam', ssl_verification=True,
               fallback_hosts=[], ssh_user='', ssh_key='', ssh_port=22,
               cluster_type='proxmox', api_port=8006)
    row['pass'] = STORED_PW
    row.update(over)
    return row


def _mgr(endpoints=None, **over):
    return mgrmod.PegaProxManager('c1', PegaProxConfig(_row(node_endpoints=endpoints or {}, **over)))


# --- normalisation -------------------------------------------------------------------

def test_a_full_entry_survives_normalisation():
    assert normalize_node_endpoints(NAT) == NAT


@pytest.mark.parametrize('raw', [
    None, [], 'node01', {'': {'ssh_port': 22}}, {'node01': 'host'}, {'node01': ['x']},
])
def test_anything_that_is_not_a_map_of_maps_normalises_away(raw):
    assert normalize_node_endpoints(raw) == {}


@pytest.mark.parametrize('port', [0, 65536, -1, 'ssh', '', None, True, False, 1.5])
def test_a_port_outside_the_range_is_dropped(port):
    assert normalize_node_endpoints({'n1': {'ssh_port': port}}) == {}


@pytest.mark.parametrize('host', [
    'https://node01.example.net',          # a scheme is not an address
    'node01.example.net/path',
    'node01.example.net:2201',            # the port belongs in its own field
    'node 01', '', '   ', None, 42,
])
def test_a_host_that_is_not_a_bare_address_is_dropped(host):
    assert normalize_node_endpoints({'n1': {'host': host}}) == {}


def test_an_entry_that_overrides_nothing_is_not_stored():
    assert normalize_node_endpoints({'n1': {}, 'n2': {'ssh_port': 2222}}) == {'n2': {'ssh_port': 2222}}


def test_a_bracketed_ipv6_address_is_stored_bare():
    assert normalize_node_endpoints({'n1': {'host': '[2001:db8::10]'}}) == {'n1': {'host': '2001:db8::10'}}


# --- what the manager dials ----------------------------------------------------------

def test_a_node_without_an_entry_keeps_the_cluster_ports():
    m = _mgr(NAT, ssh_port=2222, api_port=8086)
    assert m.ssh_port_for('node09') == 2222
    assert m.api_port_for('node09') == 8086
    assert m.ssh_port_for(None) == 2222


def test_a_node_with_an_entry_gets_its_own_ports():
    m = _mgr(NAT)
    assert (m.ssh_port_for('node01'), m.api_port_for('node01')) == (2201, 8006)
    assert (m.ssh_port_for('node02'), m.api_port_for('node02')) == (2202, 8007)


def test_half_an_entry_only_overrides_its_half():
    m = _mgr({'node01': {'ssh_port': 2201}}, ssh_port=2222, api_port=8086)
    assert m.ssh_port_for('node01') == 2201
    assert m.api_port_for('node01') == 8086


def test_a_configured_address_is_returned_without_probing(monkeypatch):
    m = _mgr(NAT)
    called = []
    monkeypatch.setattr(m, '_get_node_ip_impl', lambda n: called.append(n) or '10.40.0.99')
    assert m._get_node_ip('node02') == PUBLIC
    assert called == [], 'discovery must not run for a node that has an address'


def test_a_configured_address_is_returned_while_the_breaker_is_open(monkeypatch):
    m = _mgr(NAT)
    monkeypatch.setattr(m, '_is_node_blocked', lambda n: (True, 60))
    assert m._get_node_ip('node01') == PUBLIC


def test_a_node_without_an_address_still_goes_through_discovery(monkeypatch):
    m = _mgr({'node01': {'ssh_port': 2201}})
    monkeypatch.setattr(m, '_is_node_blocked', lambda n: (False, 0))
    monkeypatch.setattr(m, '_get_node_ip_impl', lambda n: '10.40.0.11')
    assert m._get_node_ip('node01') == '10.40.0.11'


def test_the_ssh_connection_dials_the_port_of_the_node_it_names(monkeypatch):
    """Two nodes, one address: only the node name says which port to use."""
    import paramiko

    import pegaprox.globals as ppglobals
    import pegaprox.core.ha_transport as ha_transport

    m = _mgr(NAT)   # password auth: the key branch is not what this is about
    dialled = []

    class _FakeClient(paramiko.SSHClient):
        def connect(self, **kw):
            dialled.append((kw['hostname'], kw['port']))

    fake = types.SimpleNamespace(**{k: getattr(paramiko, k) for k in dir(paramiko)
                                    if not k.startswith('__')})
    fake.SSHClient = _FakeClient
    monkeypatch.setattr(mgrmod, 'get_paramiko', lambda: fake)
    monkeypatch.setattr(ppglobals, '_ssh_semaphore', threading.BoundedSemaphore(4))
    monkeypatch.setattr(ha_transport, 'guard_client', lambda client, host: client)

    m._ssh_connect(PUBLIC, retries=1, node='node02')
    assert dialled == [(PUBLIC, 2202)], 'node02 must be dialled on its own port'

    dialled.clear()
    m._ssh_connect(PUBLIC, retries=1, node='node01')
    assert dialled == [(PUBLIC, 2201)]

    dialled.clear()
    m._ssh_connect(PUBLIC, retries=1, node='node09')
    assert dialled == [(PUBLIC, 22)], 'a node without an entry keeps the cluster port'


# --- persistence ---------------------------------------------------------------------

def test_the_map_survives_a_save_and_load(db):
    db.save_cluster('c1', _row(node_endpoints=NAT))
    assert db.get_cluster('c1')['node_endpoints'] == NAT
    assert db.get_all_clusters()['c1']['node_endpoints'] == NAT


def test_a_save_that_leaves_the_map_out_keeps_the_stored_one(db):
    db.save_cluster('c1', _row(node_endpoints=NAT))
    db.save_cluster('c1', _row())          # an unrelated edit, no endpoint map in the body
    assert db.get_cluster('c1')['node_endpoints'] == NAT


def test_an_explicit_empty_map_clears_it(db):
    db.save_cluster('c1', _row(node_endpoints=NAT))
    db.save_cluster('c1', _row(node_endpoints={}))
    assert db.get_cluster('c1')['node_endpoints'] == {}


def test_a_cluster_that_never_had_one_reads_as_empty(db):
    db.save_cluster('c1', _row())
    assert db.get_cluster('c1')['node_endpoints'] == {}


# --- the API -------------------------------------------------------------------------

@pytest.fixture
def env(api, seed, monkeypatch):
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    seed.db.save_cluster('c1', _row())
    m = mgrmod.PegaProxManager('c1', PegaProxConfig(seed.db.get_cluster('c1')))
    m.current_host = HOST
    m.is_connected = True
    m._ticket = 'PVE:root@pam:TICKET'
    api.set_manager('c1', m)
    admin = seed.user('root', role='admin')
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, c=api.as_user(admin), db=seed.db)


@pytest.mark.parametrize('method,url', [('put', '/api/clusters/c1'),
                                        ('patch', '/api/clusters/c1/config')])
def test_a_new_endpoint_address_without_the_credential_is_refused(env, method, url):
    r = getattr(env.c, method)(url, json={'node_endpoints': NAT})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'
    assert env.mgr.config.node_endpoints == {}
    assert env.mgr.config.pass_ == STORED_PW


def test_a_new_endpoint_port_without_the_credential_is_refused(env):
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': {'node01': {'ssh_port': 2201}}})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'
    assert env.mgr.config.node_endpoints == {}


def test_taking_a_port_override_away_needs_the_credential_too(env):
    """The node then answers on the cluster's port, another listener at the same address."""
    assert env.c.put('/api/clusters/c1', json={'node_endpoints': NAT, 'pass': STORED_PW}).status_code == 200
    less = {'node01': {'host': PUBLIC, 'api_port': 8006}, 'node02': NAT['node02']}
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': less})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'
    assert env.mgr.config.node_endpoints == NAT


def test_the_refusal_names_the_field_the_cluster_logs_in_with(env):
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': NAT})
    assert r.get_json().get('credential_field') == 'pass'
    env.mgr.config.api_token_user = 'root@pam!pegaprox'
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': NAT})
    assert r.get_json().get('credential_field') == 'api_token_secret'


def test_a_reconfigure_that_moves_a_node_counts_as_a_move():
    old = PegaProxConfig(_row(node_endpoints=NAT))
    same = PegaProxConfig(_row(node_endpoints=NAT))
    moved = PegaProxConfig(_row(node_endpoints={**NAT, 'node02': {'host': '198.51.100.7', 'ssh_port': 2202}}))
    assert 'node_endpoints' not in clusters_api._moved_by_reconfigure(old, same, {'node_endpoints': NAT})
    assert 'node_endpoints' in clusters_api._moved_by_reconfigure(old, moved, {'node_endpoints': {}})


def test_a_node_asked_for_in_another_case_gets_its_own_entry():
    cfg = PegaProxConfig(_row(node_endpoints={'Node02': {'ssh_port': 2202}}))
    from pegaprox.models.tasks import ssh_port_of
    assert ssh_port_of(cfg, 'node02') == 2202 and ssh_port_of(cfg, 'Node02') == 2202
    assert ssh_port_of(cfg, 'node03') == 22


def test_the_map_is_applied_when_the_credential_is_re_entered(env):
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': NAT, 'pass': STORED_PW})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert env.mgr.config.node_endpoints == NAT
    assert env.mgr.ssh_port_for('node02') == 2202


def test_an_entry_at_an_address_the_cluster_already_uses_needs_no_re_entry(env):
    """Only a move needs the credential again. The cluster host is where it already goes."""
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': {'node01': {'host': HOST}}})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert env.mgr.config.node_endpoints == {'node01': {'host': HOST}}


@pytest.mark.parametrize('body,expect', [
    ({'node_endpoints': []}, 'object keyed by node name'),
    ({'node_endpoints': {'node01': 'host'}}, 'must be an object'),
    ({'node_endpoints': {'node01': {'ssh_port': 0}}}, 'between 1 and 65535'),
    ({'node_endpoints': {'node01': {'api_port': 'eight'}}}, 'between 1 and 65535'),
    ({'node_endpoints': {'node01': {'host': 'https://n1.example.net'}}}, 'bare host name'),
    ({'node_endpoints': {'node01': {'port': 22}}}, 'unknown field'),
])
def test_a_malformed_map_is_refused_rather_than_quietly_dropped(env, body, expect):
    r = env.c.put('/api/clusters/c1', json=body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert expect in r.get_json()['error']
    assert env.mgr.config.node_endpoints == {}


def test_the_map_is_in_the_cluster_config_response(env):
    env.c.put('/api/clusters/c1', json={'node_endpoints': NAT, 'pass': STORED_PW})
    r = env.c.get('/api/clusters')
    assert r.status_code == 200, r.get_data(as_text=True)
    row = next(c for c in r.get_json() if c['id'] == 'c1')
    assert row['node_endpoints'] == NAT


def test_the_connected_cooldown_key_carries_a_port_of_its_own():
    """A slow node endpoint is marked cold under its own port, the key the reconnect checks."""
    m = _mgr(NAT)
    m.current_host = PUBLIC
    m._connected_api_port = 8007
    assert m._connected_cooldown_key() == f'[{PUBLIC}]:8007'
    m._connected_api_port = None
    m.current_host = HOST
    assert m._connected_cooldown_key() == HOST


def test_the_cooldown_key_is_the_name_the_reconnect_tried_not_its_ip():
    m = _mgr(NAT)
    m._original_host = 'pve.example.net'
    m.current_host = '198.51.100.20'
    m._connected_api_port = 8007
    assert m._connected_cooldown_key() == '[pve.example.net]:8007'
