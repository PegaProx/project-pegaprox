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
from test_remove_node_ssh_port import admin, remove  # noqa: F401 - fixtures of the remove route


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


# --- one address, one port: they go together -------------------------------------------

def test_a_nodes_own_ssh_port_goes_only_with_its_own_address():
    """At an address the node reports, or a transfer address, the forward is not in front."""
    from pegaprox.models.tasks import ssh_port_of
    cfg = PegaProxConfig(_row(node_endpoints=NAT))
    assert ssh_port_of(cfg, 'node02', PUBLIC) == 2202
    assert ssh_port_of(cfg, 'node02', f'[{PUBLIC}]') == 2202
    assert ssh_port_of(cfg, 'node02', '10.40.0.12') == 22
    # a node with a port but no address of its own has that port at whatever it reports
    cfg = PegaProxConfig(_row(node_endpoints={'node03': {'ssh_port': 2203}}))
    assert ssh_port_of(cfg, 'node03', '10.40.0.13') == 2203


@pytest.fixture
def argv(monkeypatch):
    """Every ssh command line the manager runs, nothing leaves the machine."""
    seen = []

    def node_cmd(cmd, **kw):
        seen.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout='ok\n', stderr='')
    monkeypatch.setattr(mgrmod, 'node_cmd', node_cmd)
    return seen


def _port_of(cmd):
    return int(cmd[cmd.index('-p') + 1]) if '-p' in cmd else 22


def test_the_command_line_ssh_dials_the_port_of_the_node_it_names(argv):
    m = _mgr(NAT)
    m._ssh_run_command_output(PUBLIC, 'root', 'true', node='node02')
    m._ssh_run_command(PUBLIC, 'root', 'true', node='node01')
    m._ssh_run_command_output(PUBLIC, 'root', 'true', node='node09')
    m._ssh_run_command_output('10.40.0.12', 'root', 'true', node='node02')
    assert [_port_of(c) for c in argv] == [2202, 2201, 22, 22]


def test_maintenance_mode_reaches_the_node_on_its_own_port(argv, monkeypatch):
    m = _mgr(NAT)
    monkeypatch.setattr(m, '_get_node_ip', lambda n: NAT[n]['host'])
    m._try_native_ha_maintenance('node02', types.SimpleNamespace())
    assert argv and all(PUBLIC in c and _port_of(c) == 2202 for c in argv), argv


def test_the_node_reads_reach_the_node_on_its_own_port(argv, monkeypatch):
    m = _mgr(NAT)
    monkeypatch.setattr(m, '_get_node_ip', lambda n: NAT[n]['host'])
    m._ssh_node_output('node01', 'true')
    assert argv and _port_of(argv[0]) == 2201


# --- the API port stays the cluster's ---------------------------------------------------

def test_a_failover_only_tries_hosts_on_the_clusters_api_port(monkeypatch):
    """node02 answers on 8007 only: every URL after a connect pairs the host with api_port,
    the cluster's, so it is no failover candidate. node01 at the same address on the
    cluster's port is."""
    import requests
    tried = []

    class _Session:
        def __init__(self):
            self.verify, self.headers = True, {}

        def post(self, url, **kw):
            tried.append(url)
            raise requests.exceptions.ConnectionError('down')
        get = post

    monkeypatch.setattr(mgrmod.requests, 'Session', _Session)
    m = _mgr(NAT)
    assert m.connect_to_proxmox() is False
    assert [u.split('/api2')[0] for u in tried] == [f'https://{HOST}:8006', f'https://{PUBLIC}:8006']
    assert m.api_port == 8006


# --- what moves the credential ------------------------------------------------------------

def test_a_node_at_the_cluster_host_on_a_port_of_its_own_needs_the_credential(env):
    """The address is known, the listener behind that port is not."""
    r = env.c.put('/api/clusters/c1', json={'node_endpoints': {'node01': {'host': HOST, 'ssh_port': 2201}}})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'


def test_an_endpoint_address_does_not_make_a_new_cluster_host_known(env):
    """Endpoint hosts count for the endpoint check only: the cluster host on 8006 is another
    listener than node02's forward on 2202/8007."""
    assert env.c.put('/api/clusters/c1', json={'node_endpoints': NAT, 'pass': STORED_PW}).status_code == 200
    r = env.c.put('/api/clusters/c1', json={'host': PUBLIC})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'
    assert env.mgr.config.host == HOST


def test_a_reconfigure_that_gives_a_known_address_another_port_counts_as_a_move():
    old = PegaProxConfig(_row(node_endpoints=NAT))
    moved = PegaProxConfig(_row(node_endpoints={**NAT, 'node02': {'host': PUBLIC, 'ssh_port': 2209,
                                                                  'api_port': 8007}}))
    assert 'node_endpoints' in clusters_api._moved_by_reconfigure(old, moved, {'node_endpoints': {}})


# --- what the map takes, on every way in --------------------------------------------------

@pytest.mark.parametrize('raw,expect', [
    ({'node01': {'host': '-oProxyCommand=x'}}, 'bare host name'),
    ({'node 01': {'ssh_port': 2201}}, 'node names'),
    ({'../node01': {'ssh_port': 2201}}, 'node names'),
    ({f'n{i}': {'ssh_port': 2201} for i in range(513)}, 'at most 512'),
])
def test_the_map_is_checked_beyond_its_shape(raw, expect):
    assert expect in clusters_api.node_endpoints_problem(raw)


def test_adding_a_cluster_checks_the_map(env):
    r = env.c.post('/api/clusters', json={'name': 'new', 'host': '10.40.0.50', 'user': 'root@pam',
                                          'pass': 'pw', 'node_endpoints': {'node01': {'host': '-x'}}})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'bare host name' in r.get_json()['error']


def test_a_reconfigure_checks_the_map(api, seed, monkeypatch):
    from test_ha_api import _admin, ADMIN_PW
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    seed.db.save_cluster('c1', _row())
    m = mgrmod.PegaProxManager('c1', PegaProxConfig(seed.db.get_cluster('c1')))
    api.set_manager('c1', m)
    r = _admin(api, seed).post('/api/clusters/c1/reconfigure',
                               json={'current_password': ADMIN_PW, 'name': 'lab', 'host': HOST,
                                     'user': 'root@pam', 'pass': STORED_PW,
                                     'node_endpoints': {'node01': {'host': '-x'}}})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'bare host name' in r.get_json()['error']
    assert m.config.node_endpoints == {}


def test_a_restore_takes_a_good_map_and_drops_a_bad_one(api, seed):
    import io
    import json
    import pegaprox.api.settings as settings_api
    from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password
    admin = _admin_with_password(api, seed)
    backup = {'version': '1', 'export_date': '2026-11-11T00:00:00',
              'clusters': [{**_row(node_endpoints=NAT), 'id': 'c1'},
                           {**_row(node_endpoints={'node01': {'host': '-oProxyCommand=x'}}), 'id': 'c2'}]}
    blob = settings_api._encrypt_backup(json.dumps(backup), _BACKUP_PW)
    r = admin.post('/api/config/restore', content_type='multipart/form-data',
                   data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW,
                         'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert seed.db.get_cluster('c1')['node_endpoints'] == NAT
    assert seed.db.get_cluster('c2')['node_endpoints'] == {}
    assert any('c2' in e and 'node_endpoints' in e for e in r.get_json()['errors'])


def test_a_standby_takes_the_map_over_with_the_rest_of_the_row():
    from pegaprox.core import ha
    assert 'node_endpoints' in ha._REFRESH_CLUSTER_FIELDS


# --- the node paths that dial on their own ----------------------------------------------

def test_the_ceph_fallback_goes_to_the_cluster_host_on_the_clusters_port(api):
    """No address of the node's own: the cluster host, without the node's port."""
    import pegaprox.api.ceph as ceph
    calls = []
    m = types.SimpleNamespace(raw_host=HOST, _ssh_connect=lambda ip, node=None: calls.append((ip, node)))
    with api.app.app_context():
        ceph._rbd_cmd(m, None, 'ls', node='node02')
        ceph._rbd_batch(m, None, ['ls'], node='node02')
        ceph._rbd_cmd(m, PUBLIC, 'ls', node='node02')
    assert calls == [(HOST, None), (HOST, None), (PUBLIC, 'node02')]


def test_the_replication_relay_reaches_a_node_at_its_own_address(monkeypatch):
    import pegaprox.api.vms as vms
    monkeypatch.setattr(vms, 'transfer_ssh_address', lambda *a: None)
    status = {'data': [{'type': 'node', 'name': n, 'ip': f'10.40.0.1{i}'} for i, n in enumerate(NAT)]}
    calls = []
    m = types.SimpleNamespace(config=PegaProxConfig(_row(node_endpoints=NAT)), host=HOST, api_port=8006,
                              _api_get=lambda url, **kw: types.SimpleNamespace(status_code=200,
                                                                                json=lambda: status),
                              _ssh_connect=lambda ip, node=None, **kw: calls.append((ip, node)))
    vms._xcincr_ssh(m, 'node02', 'job1')
    assert calls == [(PUBLIC, 'node02')]


def test_removing_a_node_logs_in_on_each_nodes_own_port(remove, monkeypatch):
    import test_remove_node_ssh_port as trn
    eps = {'pve1': {'host': PUBLIC, 'ssh_port': 2201}, 'pve2': {'host': PUBLIC, 'ssh_port': 2202}}
    monkeypatch.setitem(trn.NODE_IPS, 'pve1', PUBLIC)
    monkeypatch.setitem(trn.NODE_IPS, 'pve2', PUBLIC)
    assert remove(ssh_port=22, node_endpoints=eps) == [(PUBLIC, 2201, 'password'), (PUBLIC, 2202, 'password')]


def test_removing_a_node_at_an_address_it_reports_uses_the_clusters_port(remove):
    eps = {'pve1': {'host': PUBLIC, 'ssh_port': 2201}, 'pve2': {'host': PUBLIC, 'ssh_port': 2202}}
    assert remove(ssh_port=22, node_endpoints=eps) == [('10.0.0.11', 22, 'password'), ('10.0.0.12', 22, 'password')]


@pytest.mark.parametrize('endpoint,expected', [('10.0.0.12', 2202), (PUBLIC, 22)],
                         ids=['its-own-address', 'another-address'])
def test_the_main_port_shell_logs_in_on_the_nodes_own_port(api, seed, monkeypatch, endpoint, expected):
    import paramiko
    import pegaprox.api.vms as vms
    from test_node_shell_ssh_port import _stopped
    from test_node_shell_target_1143 import _cluster, _shell, _token
    dialled = []
    monkeypatch.setattr(paramiko, 'SSHClient', _stopped(dialled))
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    mgr = _cluster(api)
    mgr.config.ssh_port = 22
    mgr.config.node_endpoints = {'pve2': {'host': endpoint, 'ssh_port': 2202}}
    _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')
    assert dialled == [('10.0.0.12', expected)]
