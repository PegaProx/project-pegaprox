"""The transfer network of a cluster.

A cluster can name a network (transfer_network, a CIDR). Every remote migrate PegaProx
starts towards it - by hand, in bulk, for a cross-cluster replication, a Site Recovery
run or the cross-cluster balancer - then dials the target node at its address in that
network, pinned to the certificate the node reports for itself, instead of the
management host. A node without an address there falls back to the management host,
and the log, the audit and the answer say so. Where PegaProx relays replication data
over SSH itself it uses a node's transfer address only when the host key there is the
one pinned for the node's management address.

The setting is a cluster field, so it is round-tripped through all of its places:
save_cluster, get_cluster, get_all_clusters, PegaProxConfig, save_config, the routes
and the standby refresh.
MK Oct 2026
"""
import ast
import logging
import os
import re
import socket
import threading
import time
import types

import paramiko
import pytest

import pegaprox.core.transfer_net as xn
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig
from test_ha_api import ha_env, _audit, _standby_of_active  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CID, TGT = 'cluster_1', 'cluster_2'
NET = '10.20.0.0/24'
FP_PROXY = ':'.join(['AB'] * 32)
FP_SELF = ':'.join(['01'] * 32)


def _resp(status=200, data=None):
    return types.SimpleNamespace(status_code=status, json=lambda: {'data': data}, text='')


def _iface(name, cidr=None, cidr6=None, active=1):
    e = {'iface': name, 'type': 'bridge'}
    if cidr:
        e.update(cidr=cidr, address=cidr.split('/')[0])
    if cidr6:
        e.update(cidr6=cidr6, address6=cidr6.split('/')[0])
    if active:
        e['active'] = 1
    return e


NETS = {
    'pve1': [_iface('vmbr0', '10.0.0.11/24'), _iface('bond1', '10.20.0.11/24'), _iface('vmbr9', cidr6='fd00:20::11/64')],
    'pve2': [_iface('vmbr0', '10.0.0.12/24'), _iface('old', '10.20.0.99/24', active=0),
             _iface('bond1', '10.20.0.12/24')],
    'pve3': [_iface('vmbr0', '10.0.0.13/24')],
}
CERTS = [{'filename': 'pve-ssl.pem', 'fingerprint': FP_SELF.lower()},
         {'filename': 'pveproxy-ssl.pem', 'fingerprint': FP_PROXY.lower()}]
STATUS = [{'type': 'cluster', 'name': 'far'}] + [
    {'type': 'node', 'name': n, 'ip': f'10.0.0.1{i}'} for i, n in enumerate(('pve1', 'pve2', 'pve3'), 1)]


class _Pve:
    """The reads transfer_net makes, answered per node; counts what it was asked."""

    def __init__(self, nets=None, certs=CERTS, broken=(), options=None):
        self.nets = dict(NETS if nets is None else nets)
        self.certs, self.broken, self.calls = certs, set(broken), []
        self.options = {'migration': {'type': 'secure', 'network': '10.30.0.0/24'}} if options is None else options

    def get(self, url, **kw):
        self.calls.append(url)
        m = re.search(r'/nodes/([^/]+)/network$', url)
        if m:
            node = m.group(1)
            if node in self.broken or node not in self.nets:
                return _resp(500)
            return _resp(200, self.nets[node])
        if url.endswith('/certificates/info'):
            return _resp(200, self.certs) if self.certs is not None else _resp(403)
        if url.endswith('/cluster/status'):
            return _resp(200, STATUS)
        if url.endswith('/cluster/options'):
            return _resp(200, self.options)
        raise AssertionError(f'unexpected read {url}')

    def reads(self, kind='/network'):
        return [u for u in self.calls if u.endswith(kind)]


def _manager(cid=TGT, transfer=NET, nodes=('pve1', 'pve2', 'pve3'), pve=None, host='10.0.0.11', **cfg):
    m = object.__new__(PegaProxManager)
    m.id = cid
    m.current_host = None
    m.logger = logging.getLogger('test.transfer_net')
    conf = {'name': f'name-{cid}', 'host': host, 'user': 'root@pam', 'pass': 'pw', 'transfer_network': transfer}
    conf.update(cfg)
    m.config = PegaProxConfig(conf)
    m._cached_node_dict = {n: {'node': n, 'status': 'online'} for n in nodes}
    m._nodes_cache_time = time.time() + 10 ** 6
    m.is_connected = True
    m.session = object()
    m._node_failures, m._node_blocked_until, m._node_lock = {}, {}, threading.RLock()
    m.pve = pve or _Pve()
    m._api_get = m.pve.get
    return m


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch):
    for store in (xn._nets, xn._certs, xn._options, xn._ssh_away, xn._reported):
        store.clear()
    xn._refreshing.clear()
    # the background read of the settings view runs in place here
    monkeypatch.setattr(xn, '_spawn', lambda fn: fn())
    yield


# --- the setting ----------------------------------------------------------------------------

@pytest.mark.parametrize('value,expected', [
    ('10.20.0.0/24', '10.20.0.0/24'), (' 10.20.0.7/24 ', '10.20.0.0/24'), ('fd00:20::1/64', 'fd00:20::/64'),
    ('', ''), (None, ''), ('   ', ''),
])
def test_a_network_is_stored_as_its_network_address(value, expected):
    assert xn.normalize(value) == (expected, None)


@pytest.mark.parametrize('value', ['10.20.0.1', '10.20.0.0/33', 'not-a-net/24', '0.0.0.0/0', '::/0',
                                   '127.0.0.0/8', 'fe80::/64', '169.254.0.0/16', '224.0.0.0/4',
                                   'x' * 70 + '/24', 5, ['10.0.0.0/8'], {'a': 1}, True])
def test_anything_else_is_refused(value):
    cidr, err = xn.normalize(value)
    assert cidr is None and err


def test_the_setting_survives_save_reload_and_an_old_backup(db):
    base = {'name': 'far', 'host': '10.0.0.11', 'user': 'root@pam', 'pass': 'pw', 'transfer_network': NET}
    db.save_cluster(TGT, base)
    assert db.get_cluster(TGT)['transfer_network'] == NET
    assert db.get_all_clusters()[TGT]['transfer_network'] == NET
    # a restore from a backup that predates the field keeps what is stored
    db.save_cluster(TGT, {k: v for k, v in base.items() if k != 'transfer_network'})
    assert db.get_cluster(TGT)['transfer_network'] == NET
    db.save_cluster(TGT, dict(base, transfer_network=''))
    assert db.get_cluster(TGT)['transfer_network'] == ''


def test_the_round_trip_reaches_the_endpoint(db):
    """save_cluster -> get_cluster -> PegaProxConfig -> the host a remote migrate dials."""
    db.save_cluster(TGT, {'name': 'far', 'host': '10.0.0.11', 'user': 'root@pam', 'pass': 'pw',
                          'transfer_network': NET})
    m = _manager()
    m.config = PegaProxConfig(db.get_cluster(TGT))
    assert m.config.transfer_network == NET
    route = xn.migration_route(m, 'pve2')
    assert (route['host'], route['iface'], route['fingerprint']) == ('10.20.0.12', 'bond1', FP_PROXY)
    token = {'token_id': 'root@pam!t', 'token_value': 's3'}
    assert xn.endpoint(token, route['host'], route['fingerprint']) == \
        f'apitoken=PVEAPIToken=root@pam!t=s3,host=10.20.0.12,fingerprint={FP_PROXY}'


def test_a_synced_network_reaches_the_running_manager(db, monkeypatch):
    # a standby hands the synced row to its managers field by field
    from pegaprox.core import ha
    import pegaprox.globals as g
    db.save_cluster(TGT, {'name': 'far', 'host': 'h', 'user': 'u', 'pass': 'p', 'transfer_network': NET})
    cfg = PegaProxConfig({'name': 'far', 'host': 'h', 'user': 'u'})
    monkeypatch.setitem(g.cluster_managers, TGT, types.SimpleNamespace(config=cfg))
    ha._refresh_managers()
    assert cfg.transfer_network == NET


# --- the routes that set it -------------------------------------------------------------------

@pytest.fixture
def conf(api, seed):
    seed.db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = PegaProxManager(CID, PegaProxConfig(seed.db.get_cluster(CID)))
    api.set_manager(CID, m)
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, db=seed.db)


def test_an_admin_sets_it_and_it_is_kept(conf):
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    r = c.patch(f'/api/clusters/{CID}/config', json={'transfer_network': '10.20.0.5/24'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['updated_fields'] == ['transfer_network']
    assert conf.mgr.config.transfer_network == NET
    assert conf.db.get_cluster(CID)['transfer_network'] == NET            # through save_config
    listed = next(x for x in c.get('/api/clusters').get_json() if x['id'] == CID)
    assert listed['transfer_network'] == NET
    assert c.get(f'/api/clusters/{CID}/config/export').get_json()['transfer_network'] == NET
    assert any('transfer_network' in a['details'] for a in _audit('cluster.config_changed'))
    # and off again
    assert c.put(f'/api/clusters/{CID}', json={'transfer_network': ''}).status_code == 200
    assert conf.mgr.config.transfer_network == '' and conf.db.get_cluster(CID)['transfer_network'] == ''


@pytest.mark.parametrize('method,url', [('patch', f'/api/clusters/{CID}/config'), ('put', f'/api/clusters/{CID}')])
@pytest.mark.parametrize('value', ['10.20.0.1', '0.0.0.0/0', 'fe80::/64', 7, ['10.0.0.0/8'], 'a/b'])
def test_a_malformed_network_is_a_400(conf, method, url, value):
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    r = getattr(c, method)(url, json={'transfer_network': value, 'name': 'renamed'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert conf.mgr.config.transfer_network == '' and conf.mgr.config.name == 'lab'


def test_an_xcpng_pool_takes_none(conf):
    conf.mgr.cluster_type = 'xcpng'
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    r = c.patch(f'/api/clusters/{CID}/config', json={'transfer_network': NET})
    assert r.status_code == 400 and 'Proxmox VE' in r.get_json()['error']
    assert c.get(f'/api/clusters/{CID}/transfer-network').status_code == 400


@pytest.mark.parametrize('who', ['viewer', 'confined-admin', 'other-tenant', 'pool-scoped'])
def test_who_may_not_set_it(conf, who):
    seed = conf.seed
    if who == 'viewer':
        user = seed.user('vicky', role='viewer')
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    elif who == 'other-tenant':
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme', permissions=['cluster.config'])
    else:
        seed.tenant('acme', clusters=[CID])
        seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'cluster.config'])
        user = seed.user('mallory', role='user', tenant_id='acme', permissions=['cluster.config'])
    r = conf.api.as_user(user).patch(f'/api/clusters/{CID}/config', json={'transfer_network': NET})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert conf.mgr.config.transfer_network == ''


def test_a_standby_sets_none(ha_env, seed):  # noqa: F811
    api = ha_env.api
    seed.db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = PegaProxManager(CID, PegaProxConfig(seed.db.get_cluster(CID)))
    api.set_manager(CID, m)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.patch(f'/api/clusters/{CID}/config', json={'transfer_network': NET})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert m.config.transfer_network == ''


# --- where a migration dials -------------------------------------------------------------------

def test_the_node_address_inside_the_network_and_its_own_certificate():
    m = _manager()
    route = xn.migration_route(m, 'pve2')
    # an interface that is up wins over one that is down with an address in the network too
    assert route['host'] == '10.20.0.12' and route['iface'] == 'bond1'
    # pveproxy's own certificate over the self-signed one, the order pveproxy uses
    assert route['fingerprint'] == FP_PROXY
    assert route['reason'] is None and route['node'] == 'pve2'
    six = _manager('six', transfer='fd00:20::/64')
    assert xn.migration_route(six, 'pve1')['host'] == 'fd00:20::11'
    # only pve-ssl.pem
    only = _manager('only', pve=_Pve(certs=[CERTS[0]]))
    assert xn.migration_route(only, 'pve1')['fingerprint'] == FP_SELF


def test_a_cluster_without_the_setting_keeps_its_management_host():
    m = _manager(transfer='')
    assert xn.migration_route(m, 'pve2') is None
    assert xn.describe(None) is None and m.pve.calls == []


@pytest.mark.parametrize('node,pve,reason', [
    ('pve3', None, 'no_address'),
    ('pve2', _Pve(broken={'pve2'}), 'unreadable'),
    ('pve2', _Pve(certs=None), 'no_certificate'),
    ('elsewhere', None, 'not_member'),
])
def test_a_node_without_a_usable_address_falls_back_and_says_why(node, pve, reason):
    m = _manager(pve=pve)
    route = xn.migration_route(m, node)
    assert route['host'] is None and route['fingerprint'] is None and route['reason'] == reason
    assert NET in route['note'] and 'management host' in route['note']
    assert xn.describe(route) == {'network': NET, 'node': node, 'via': 'management', 'host': None,
                                  'reason': reason}
    if reason == 'not_member':
        assert m.pve.calls == []     # no read for a name the cluster does not have


def test_a_run_without_a_target_node_goes_to_the_node_behind_the_management_host():
    m = _manager('behind2', host='10.0.0.12')
    assert xn.migration_route(m)['node'] == 'pve2'
    # that node has no address in the network: the first online node that has one
    m3 = _manager('behind3', host='10.0.0.13')
    route = xn.migration_route(m3)
    assert (route['node'], route['host']) == ('pve1', '10.20.0.11')
    # none has one: it says so
    none = _manager('none', pve=_Pve(nets={n: NETS['pve3'] for n in NETS}))
    assert xn.migration_route(none)['reason'] == 'no_address'


def test_a_node_network_is_read_once_in_ten_minutes(monkeypatch):
    m = _manager()
    for _ in range(5):
        xn.migration_route(m, 'pve2')
    assert len(m.pve.reads()) == 1 and len(m.pve.reads('/certificates/info')) == 1
    later = time.time() + xn.TTL + 1
    monkeypatch.setattr(xn.time, 'time', lambda: later)
    xn.migration_route(m, 'pve2')
    assert len(m.pve.reads()) == 2


def test_a_fallback_is_logged_each_time_and_audited_once_an_hour(db, caplog):
    m = _manager()
    route = xn.migration_route(m, 'pve3')
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            xn.report_fallback(route, m.logger, user='root')
    assert sum('transfer network' in r.getMessage() for r in caplog.records) == 3
    rows = _audit('migration.transfer_network_fallback')
    assert len(rows) == 1 and 'pve3 has no address' in rows[0]['details'] and rows[0]['user'] == 'root'
    # a route that has an address reports nothing
    xn.report_fallback(xn.migration_route(m, 'pve2'), m.logger)
    assert len(_audit('migration.transfer_network_fallback')) == 1


# --- the call sites -----------------------------------------------------------------------------

_SITES = [
    ('pegaprox/api/vms.py', 'cross_cluster_migrate_api'),
    ('pegaprox/api/vms.py', '_execute_replication'),
    ('pegaprox/background/site_recovery.py', '_migrate_vm_cross_cluster'),
    ('pegaprox/background/cross_cluster_lb.py', 'run_cross_cluster_balance_check'),
]


def _functions(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as fh:
        tree = ast.parse(fh.read())
    return {f.name: f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)}


def _calls(fn, name):
    return [c for c in ast.walk(fn) if isinstance(c, ast.Call)
            and (getattr(c.func, 'attr', None) or getattr(c.func, 'id', None)) == name]


def test_every_remote_migrate_pegaprox_builds_an_endpoint_for_asks_the_transfer_network():
    found = set()
    for path in ('pegaprox/api/vms.py', 'pegaprox/background/site_recovery.py',
                 'pegaprox/background/cross_cluster_lb.py'):
        for name, fn in _functions(path).items():
            if _calls(fn, 'remote_migrate_vm'):
                found.add((path, name))
    # the raw route takes the endpoint from its caller and names no cluster to look up
    assert found - set(_SITES) == {('pegaprox/api/vms.py', 'remote_migrate_vm_api')}
    for path, name in _SITES:
        fn = _functions(path)[name]
        assert _calls(fn, 'migration_route') and _calls(fn, 'endpoint') and _calls(fn, 'report_fallback'), name
        assert 'PVEAPIToken' not in ast.unparse(fn), name


def _source(cid=CID):
    from conftest import make_fake_manager
    src = make_fake_manager(cid)
    src.get_vm_config.return_value = {'success': False}
    src.remote_migrate_vm.return_value = {'success': True, 'task': 'UPID:pve1:1:qmigrate'}
    src.logger = logging.getLogger('test.transfer_net.src')
    return src


def _target(api, transfer=NET, pve=None):
    tgt = _manager(TGT, transfer=transfer, pve=pve)
    tgt.create_api_token = lambda name: {'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}
    tgt.delete_api_token = lambda name: {'success': True}
    tgt.fp_asked = 0

    def fingerprint():
        tgt.fp_asked += 1
        return {'success': True, 'host': '10.0.0.11', 'fingerprint': FP_SELF, 'port': 8006}
    tgt.get_cluster_fingerprint = fingerprint
    api.set_manager(TGT, tgt)
    return tgt


@pytest.fixture
def xc(api, seed, monkeypatch):
    import pegaprox.api.vms as vms
    import threading as _threading
    # the token cleanup thread of a started migration polls for hours
    fake = types.SimpleNamespace(**{k: getattr(_threading, k) for k in dir(_threading) if not k.startswith('__')})
    fake.Thread = lambda *a, **k: types.SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(vms, 'threading', fake)
    src = api.set_manager(CID, _source())
    admin = api.as_user(seed.user('root', role='admin'))

    def run(target_node='pve2', **body):
        data = {'source_cluster': CID, 'target_cluster': TGT, 'vmid': 100, 'vm_type': 'qemu',
                'source_node': 'pve1', 'target_node': target_node, 'target_storage': 'local-lvm',
                'delete_source': False}
        data.update(body)
        return admin.post('/api/cross-cluster-migrate', json=data)
    return types.SimpleNamespace(api=api, src=src, run=run)


def _endpoint_of(src):
    return src.remote_migrate_vm.call_args[0][3]


def test_a_migration_by_hand_goes_over_the_transfer_network(xc):
    tgt = _target(xc.api)
    r = xc.run()
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _endpoint_of(xc.src) == f'apitoken=PVEAPIToken=root@pam!{_token_name(xc.src)}=secret,' \
                                   f'host=10.20.0.12,fingerprint={FP_PROXY}'
    assert tgt.fp_asked == 0
    assert r.get_json()['transfer_network'] == {'network': NET, 'node': 'pve2', 'via': 'transfer',
                                                'host': '10.20.0.12', 'reason': None}
    assert 'warnings' not in r.get_json()
    assert _audit('migration.transfer_network_fallback') == []


def _token_name(src):
    return re.search(r'root@pam!([^=]+)=', src.remote_migrate_vm.call_args[0][3]).group(1)


def test_a_target_node_without_an_address_goes_to_the_management_host_and_says_so(xc):
    tgt = _target(xc.api)
    r = xc.run(target_node='pve3')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'host=10.0.0.11,fingerprint=' + FP_SELF in _endpoint_of(xc.src)
    assert tgt.fp_asked == 1
    body = r.get_json()
    assert body['transfer_network']['via'] == 'management' and body['transfer_network']['reason'] == 'no_address'
    assert any('pve3 has no address' in w for w in body['warnings'])
    assert len(_audit('migration.transfer_network_fallback')) == 1


def test_without_the_setting_nothing_changes(xc):
    tgt = _target(xc.api, transfer='')
    r = xc.run()
    assert r.status_code == 200
    assert 'host=10.0.0.11,' in _endpoint_of(xc.src) and tgt.fp_asked == 1
    assert 'transfer_network' not in r.get_json()
    # none of its reads: the migration preflight reads the target's node list, nothing else here
    assert [u for u in tgt.pve.calls if not u.endswith('/api2/json/nodes')] == []


def test_a_site_recovery_migration_goes_over_the_transfer_network(monkeypatch):
    import pegaprox.background.site_recovery as sr
    import pegaprox.api.vms as vms
    src = _source()
    src.get_node_status.return_value = {'pve1': {}}
    src.get_vms.return_value = [{'vmid': 100}]
    src.remote_migrate_vm.return_value = {'success': True, 'task': 'UPID:x'}
    monkeypatch.setattr(vms, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    import gevent
    monkeypatch.setattr(gevent, 'spawn', lambda *a, **k: None)
    tgt = _manager(TGT, host='10.0.0.12')
    tgt.create_api_token = lambda name: {'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}
    tgt.get_cluster_fingerprint = lambda: pytest.fail('the management host is not asked')
    ok, err = sr._migrate_vm_cross_cluster(src, tgt, 100, 'qemu', {}, {})
    assert ok, err
    endpoint = src.remote_migrate_vm.call_args[1]['target_endpoint']
    # no target node in a recovery plan: the node behind the management host
    assert f'host=10.20.0.12,fingerprint={FP_PROXY}' in endpoint


# --- the SSH relay ---------------------------------------------------------------------------

def test_the_relay_address_is_a_member_address_in_the_network():
    m = _manager()
    assert xn.transfer_ssh_address(m, 'pve2', '10.0.0.12') == '10.20.0.12'
    assert xn.transfer_ssh_address(m, 'pve3', '10.0.0.13') is None
    assert xn.transfer_ssh_address(m, 'stranger', '10.0.0.12') is None
    # never the management address handed in
    assert xn.transfer_ssh_address(m, 'pve2', '10.20.0.12') is None
    assert xn.transfer_ssh_address(_manager(transfer=''), 'pve2', '10.0.0.12') is None
    xn.ssh_unusable(m, 'pve2', '10.20.0.12')
    assert xn.transfer_ssh_address(m, 'pve2', '10.0.0.12') is None


def test_the_relay_falls_back_to_the_management_address(monkeypatch):
    import pegaprox.api.vms as vms
    m = _manager()
    monkeypatch.setattr(vms, '_xcincr_node_ip', lambda mgr, node: '10.0.0.12')
    tried = []

    def connect(host, **kw):
        tried.append((host, kw.get('pinned_as')))
        if kw.get('pinned_as'):
            kw['failure'].update(kind='host_key', detail='not the pinned key')
            return None
        return 'mgmt-client'
    m._ssh_connect = connect
    assert vms._xcincr_ssh(m, 'pve2', 'j1') == 'mgmt-client'
    assert tried == [('10.20.0.12', '10.0.0.12'), ('10.0.0.12', None)]
    # and for the next ten minutes straight to the management address
    tried.clear()
    assert vms._xcincr_ssh(m, 'pve2', 'j1') == 'mgmt-client'
    assert tried == [('10.0.0.12', None)]


def test_the_relay_uses_the_transfer_address_it_reaches(monkeypatch):
    import pegaprox.api.vms as vms
    m = _manager()
    monkeypatch.setattr(vms, '_xcincr_node_ip', lambda mgr, node: '10.0.0.12')
    m._ssh_connect = lambda host, **kw: f'client@{host}'
    assert vms._xcincr_ssh(m, 'pve2', 'j1') == 'client@10.20.0.12'


class _Sshd(paramiko.ServerInterface):
    def __init__(self):
        self.logins = []

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        self.logins.append((username, password))
        return paramiko.AUTH_SUCCESSFUL


def _serve(host_key):
    """A one-connection SSH server on a free loopback port with this host key."""
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(1)
    sock.settimeout(15)
    sshd = _Sshd()

    def run():
        try:
            conn, _ = sock.accept()
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            t.start_server(server=sshd)
            t.accept(5)
            while t.is_active():
                time.sleep(0.05)
        except Exception:
            pass
        finally:
            sock.close()
    threading.Thread(target=run, daemon=True).start()
    return sock.getsockname()[1], sshd


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    import pegaprox.utils.ssh_security as sec
    import pegaprox.globals as _g
    path = str(tmp_path / 'known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    monkeypatch.setattr(sec, 'strict_host_keys_enabled', lambda: False)
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4), raising=False)
    return path


def _pin(path, name, key):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    hk.add(name, key.get_name(), key)
    hk.save(path)


_KEYS = {}


def _key(name):
    if name not in _KEYS:
        _KEYS[name] = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, 'generate') \
            else paramiko.RSAKey.generate(1024)
    return _KEYS[name]


def _ssh_manager(port):
    m = object.__new__(PegaProxManager)
    m.id = 'ssh'
    m.logger = logging.getLogger('test.transfer_net.ssh')
    m.config = PegaProxConfig({'name': 'ssh', 'host': '10.0.0.12', 'user': 'root@pam', 'pass': 'pw',
                               'ssh_port': port})
    return m


def test_a_transfer_address_with_the_node_key_is_used(known_hosts):
    node = paramiko.RSAKey.generate(1024)
    port, sshd = _serve(node)
    _pin(known_hosts, f'[10.0.0.12]:{port}', node)
    before = open(known_hosts).read()
    client = _ssh_manager(port)._ssh_connect('127.0.0.1', retries=1, connect_timeout=10, pinned_as='10.0.0.12')
    assert client is not None
    client.close()
    assert sshd.logins == [('root', 'pw')]
    # nothing learned under the transfer address
    assert open(known_hosts).read() == before


def test_another_key_there_gets_no_password(known_hosts):
    port, sshd = _serve(paramiko.RSAKey.generate(1024))
    _pin(known_hosts, f'[10.0.0.12]:{port}', paramiko.RSAKey.generate(1024))
    before = open(known_hosts).read()
    failure = {}
    client = _ssh_manager(port)._ssh_connect('127.0.0.1', retries=1, connect_timeout=10, failure=failure,
                                             pinned_as='10.0.0.12')
    assert client is None and failure['kind'] == 'host_key'
    assert sshd.logins == []
    assert open(known_hosts).read() == before


def test_another_key_type_there_gets_no_password_either(known_hosts):
    port, sshd = _serve(paramiko.ECDSAKey.generate())
    _pin(known_hosts, f'[10.0.0.12]:{port}', paramiko.RSAKey.generate(1024))
    failure = {}
    client = _ssh_manager(port)._ssh_connect('127.0.0.1', retries=1, connect_timeout=10, failure=failure,
                                             pinned_as='10.0.0.12')
    assert client is None and failure['kind'] == 'host_key' and sshd.logins == []


def test_a_transfer_address_gets_the_password_of_its_node(known_hosts, monkeypatch):
    """A node with a root password of its own (#1136) gets it at its transfer address too:
    the login there is credited to the management address the host key was held to."""
    node = paramiko.RSAKey.generate(1024)
    port, sshd = _serve(node)
    _pin(known_hosts, f'[10.0.0.12]:{port}', node)
    import pegaprox.core.node_creds as node_creds
    monkeypatch.setattr(node_creds, 'secrets_of', lambda cid: {'pve2': 'node-pw'} if cid == 'ssh' else {})
    m = _ssh_manager(port)
    asked = []

    def own(addr):
        asked.append(addr)
        return 'node-pw' if addr == '10.0.0.12' else ''
    m._own_password_at = own
    client = m._ssh_connect('127.0.0.1', retries=1, connect_timeout=10, pinned_as='10.0.0.12')
    assert client is not None
    client.close()
    assert sshd.logins == [('root', 'node-pw')]
    assert '127.0.0.1' not in asked


def test_no_pin_for_the_management_address_means_no_connection(known_hosts):
    port, sshd = _serve(paramiko.RSAKey.generate(1024))
    failure = {}
    client = _ssh_manager(port)._ssh_connect('127.0.0.1', retries=1, connect_timeout=10, failure=failure,
                                             pinned_as='10.0.0.12')
    assert client is None and failure == {'kind': 'host_key', 'detail': 'no host key pinned for 10.0.0.12'}
    assert sshd.logins == [] and not os.path.exists(known_hosts)


# --- the settings view -------------------------------------------------------------------------

ROUTE = f'/api/clusters/{TGT}/transfer-network'


@pytest.fixture
def view(api, seed):
    tgt = api.set_manager(TGT, _manager(TGT))
    return types.SimpleNamespace(api=api, seed=seed, mgr=tgt,
                                 admin=api.as_user(seed.user('root', role='admin')))


def test_the_view_reads_in_the_background_and_then_from_the_cache(view, monkeypatch):
    spawned = []
    monkeypatch.setattr(xn, '_spawn', spawned.append)
    first = view.admin.get(ROUTE)
    assert first.status_code == 200, first.get_data(as_text=True)
    body = first.get_json()
    assert body['pending'] is True and {n['state'] for n in body['nodes']} == {'pending'}
    assert view.mgr.pve.reads() == [] and len(spawned) == 1
    # a second request while the read runs starts no second one
    view.admin.get(ROUTE)
    assert len(spawned) == 1
    spawned[0]()
    body = view.admin.get(ROUTE).get_json()
    assert body['pending'] is False and body['network'] == NET and body['saved'] == NET
    rows = {n['node']: n for n in body['nodes']}
    assert (rows['pve1']['state'], rows['pve1']['address'], rows['pve1']['iface']) == ('ok', '10.20.0.11', 'bond1')
    assert rows['pve3']['state'] == 'none' and body['missing'] == 1
    assert body['migration_network'] == '10.30.0.0/24'
    reads = len(view.mgr.pve.reads())
    assert reads == 3
    for _ in range(5):
        view.admin.get(ROUTE)
    assert len(view.mgr.pve.reads()) == reads and len(spawned) == 1


def test_the_view_previews_another_network(view):
    view.admin.get(ROUTE)
    body = view.admin.get(ROUTE + '?network=10.0.0.0/24').get_json()
    assert body['network'] == '10.0.0.0/24' and body['saved'] == NET and body['missing'] == 0
    off = view.admin.get(ROUTE + '?network=').get_json()
    assert off['network'] == '' and {n['state'] for n in off['nodes']} == {'off'}
    r = view.admin.get(ROUTE + '?network=10.0.0.1')
    assert r.status_code == 400 and 'network' in r.get_json()['error']


def test_the_datacenter_migration_network_reads_both_shapes(view):
    view.mgr.pve.options = {'migration': 'type=insecure,network=10.40.0.0/24'}
    assert view.admin.get(ROUTE).get_json()['migration_network'] == '10.40.0.0/24'
    xn._options.clear()
    view.mgr.pve.options = {}
    assert view.admin.get(ROUTE).get_json()['migration_network'] == ''


@pytest.mark.parametrize('who,status', [('viewer', 200), ('no-cluster-view', 403), ('confined-admin', 403),
                                        ('other-tenant', 403), ('pool-scoped', 403)])
def test_who_sees_the_node_addresses(view, who, status):
    seed = view.seed
    if who == 'viewer':
        user = seed.user('vicky', role='viewer')
    elif who == 'no-cluster-view':
        user = seed.user('nora', role='viewer', denied=['cluster.view'])
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    elif who == 'other-tenant':
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme', permissions=['cluster.view'])
    else:
        seed.tenant('acme', clusters=[TGT])
        seed.pool(TGT, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
        user = seed.user('mallory', role='viewer', tenant_id='acme')
    assert view.api.as_user(user).get(ROUTE).status_code == status


def test_an_unknown_cluster_is_a_404(view):
    assert view.admin.get('/api/clusters/nope/transfer-network').status_code == 404


# --- the reachability check --------------------------------------------------------------------

CHECK = f'/api/clusters/{TGT}/transfer-network/check'


@pytest.fixture
def chk(view):
    src = _manager(CID, transfer='', nodes=('a1', 'a2'), host='10.9.0.1')
    src.ran = []

    def run(node, cmd, timeout=60):
        src.ran.append((node, cmd))
        return src.answer
    src.answer = ('0 ok 3\n1 fail 4001\n', None)
    src._ssh_node_output_ex = run
    view.api.set_manager(CID, src)
    view.src = src
    return view


def test_the_check_tests_each_transfer_address_from_one_node(chk):
    r = chk.admin.post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    rows = {n['node']: n for n in body['nodes']}
    assert (rows['pve1']['status'], rows['pve1']['ms']) == ('ok', 3)
    assert rows['pve2']['status'] == 'fail' and rows['pve3'] == {'node': 'pve3', 'address': None, 'status': 'none'}
    assert body['network'] == NET and body['port'] == 8006 and body['source_node'] == 'a1'
    (node, cmd), = chk.src.ran
    assert node == 'a1'
    assert '/dev/tcp/10.20.0.11/8006' in cmd and '/dev/tcp/10.20.0.12/8006' in cmd
    assert '10.0.0.' not in cmd
    audit = _audit('cluster.transfer_network_check')
    assert len(audit) == 1 and '1 answer, 1 do not, 1 without an address' in audit[0]['details']


@pytest.mark.parametrize('body,status', [
    ({}, 400), ({'source_cluster': CID}, 400), ({'source_cluster': CID, 'source_node': 'a1;reboot'}, 400),
    ({'source_cluster': 5, 'source_node': 'a1'}, 400), ({'source_cluster': CID, 'source_node': ['a1']}, 400),
    ({'source_cluster': 'x' * 65, 'source_node': 'a1'}, 400), ({'source_cluster': 'nope', 'source_node': 'a1'}, 404),
    ({'source_cluster': CID, 'source_node': 'pve1'}, 400),
])
def test_a_malformed_check_is_refused(chk, body, status):
    r = chk.admin.post(CHECK, json=body)
    assert r.status_code == status, r.get_data(as_text=True)
    assert chk.src.ran == []


def test_the_check_says_why_it_could_not_run(chk):
    chk.src.answer = (None, 'SSH connection failed')
    r = chk.admin.post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 502 and r.get_json()['code'] == 'SSH_FAILED'
    chk.src.config.ssh_disabled = True
    r = chk.admin.post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 409 and r.get_json()['code'] == 'SSH_DISABLED'
    assert len(chk.src.ran) == 1
    chk.mgr.config.transfer_network = ''
    r = chk.admin.post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 409 and r.get_json()['code'] == 'NO_NETWORK'


@pytest.mark.parametrize('who', ['viewer', 'confined-admin', 'other-tenant', 'pool-scoped-on-source'])
def test_who_may_not_run_the_check(chk, who):
    seed = chk.seed
    if who == 'viewer':
        user = seed.user('vicky', role='viewer')
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    elif who == 'other-tenant':
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme', permissions=['cluster.config'])
    else:
        # whole-cluster operator of the target, a pool on the source only
        seed.tenant('acme', clusters=[TGT, CID])
        seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
        user = seed.user('mallory', role='user', tenant_id='acme', permissions=['cluster.config'])
    r = chk.api.as_user(user).post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert chk.src.ran == []


def test_a_standby_runs_no_check(ha_env, seed):  # noqa: F811
    api = ha_env.api
    api.set_manager(TGT, _manager(TGT))
    src = api.set_manager(CID, _manager(CID, transfer='', nodes=('a1',)))
    src._ssh_node_output_ex = lambda *a, **k: pytest.fail('a standby logs in nowhere')
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post(CHECK, json={'source_cluster': CID, 'source_node': 'a1'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def test_the_probe_reaches_the_shell_with_checked_addresses_only():
    with pytest.raises(ValueError):
        xn.probe_command(['10.0.0.1; reboot'])
    assert xn.parse_probe('0 ok 12\n1 fail 4000\ngarbage\n7 ok 1\n2 maybe 3\n', 3) == {0: (True, 12), 1: (False, 4000)}
