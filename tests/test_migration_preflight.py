"""The migration preflight: one verdict per guest before anything moves.

POST /api/clusters/<cid>/migration-preflight and POST /api/cross-cluster-migrate/preflight
answer per guest ready, warning or blocked with the reasons, the totals, what the target
nodes hold afterwards and the steps a run takes (core/preflight.py). dry_run on the bulk
and the cross-cluster migration answers the same without starting anything, and the real
runs skip what it blocks unless the caller overrides a block that may be overridden.

The clusters are faked at the API: every read the preflight makes is answered from the
tables below and counted.

MK Oct 2026
"""
import re
import threading
import types

import pytest

from test_ha_api import ha_env, _standby_of_active, _audit  # noqa: F401 (ha_env is a fixture)

import pegaprox.api.clusters as clusters_api
import pegaprox.core.preflight as pf
import pegaprox.core.transfer_net as xn
from pegaprox.core import bulk_migrate as bulk

CID, TGT = 'cluster_1', 'cluster_2'
GB = 1024 ** 3


class _Resp:
    def __init__(self, status, data=None):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


def _node(mem_used_gb=8, mem_total_gb=64, cpus=16, model='Intel(R) Xeon(R) Gold 6230', **kw):
    d = {'status': 'online', 'mem_used': mem_used_gb * GB, 'mem_total': mem_total_gb * GB, 'mem_percent': 0,
         'cpu_percent': 10.0, 'cpuinfo': {'cpus': cpus, 'model': model}, 'maintenance_mode': False}
    d.update(kw)
    return d


def _guest(vmid, node='pve1', kind='qemu', status='running', mem_gb=4, cpus=2, **kw):
    g = {'vmid': vmid, 'name': f'g{vmid}', 'type': kind, 'node': node, 'status': status,
         'maxmem': mem_gb * GB, 'maxcpu': cpus, 'cpu': 0.1, 'maxdisk': 32 * GB}
    g.update(kw)
    return g


def _store(node, storage, shared=False, plugintype='lvmthin', content='images,rootdir', free_gb=500, **kw):
    s = {'storage': storage, 'node': node, 'status': 'available', 'shared': 1 if shared else 0,
         'plugintype': plugintype, 'content': content, 'disk': 0, 'maxdisk': free_gb * GB}
    s.update(kw)
    return s


def _net(*bridges):
    return [{'iface': b, 'type': 'bridge', 'active': 1} for b in bridges] + [{'iface': 'eno1', 'type': 'eth'}]


class _Pve:
    """A Proxmox cluster as far as the preflight and a migration read and call it"""

    def __init__(self, api, cid=CID, guests=(), nodes=None, configs=None, storages=None, networks=None,
                 vnets=(), ha_resources=(), ha_rules=(), ha_groups=(), replication=(), name=None, **cfg):
        self.id = self.cluster_id = cid
        self.cluster_type = 'proxmox'
        self.host, self.api_port = '192.0.2.10', 8006
        self.is_connected = True
        self.session = object()
        self.logger = __import__('logging').getLogger('test.preflight')
        conf = {'name': name or cid, 'cpu_baseline': None, 'backup_sla_max_age_hours': 0, 'excluded_nodes': [],
                'transfer_network': '', 'user': 'root@pam'}
        conf.update(cfg)
        self.config = types.SimpleNamespace(**conf)
        self.guests = {g['vmid']: dict(g) for g in guests}
        self.node_status = nodes if nodes is not None else {'pve1': _node(), 'pve2': _node(), 'pve3': _node()}
        self.nodes = {n: {'node': n, 'status': d.get('status')} for n, d in self.node_status.items()}
        self.configs = configs or {}
        self.storages = storages if storages is not None else [
            _store(n, s) for n in self.node_status for s in ('local-lvm',)] + [
            _store(n, 'ceph', shared=True, plugintype='rbd', content='images') for n in self.node_status]
        self.networks = networks if networks is not None else {n: _net('vmbr0') for n in self.node_status}
        self.vnets, self.ha_resources, self.ha_rules = list(vnets), list(ha_resources), list(ha_rules)
        self.ha_groups, self.replication = list(ha_groups), list(replication)
        self.reads, self.config_reads, self.started, self.tokens = [], [], [], []
        self.lock = threading.Lock()
        api.set_manager(cid, self)

    # the reads
    def get_vm_resources(self, max_age=0):
        return [dict(g) for g in self.guests.values()]

    def get_node_status(self):
        return {k: dict(v) for k, v in self.node_status.items()}

    def placement_pool(self, node_status, drop=()):
        return {n: d for n, d in node_status.items() if d.get('status') == 'online'
                and not d.get('maintenance_mode') and n not in drop}

    def _guest_config(self, node, vmid, kind):
        with self.lock:
            self.config_reads.append(vmid)
        cfg = self.configs.get(vmid)
        return dict(cfg) if cfg is not None else None

    def _api_get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        with self.lock:
            self.reads.append(path)
        if path == '/cluster/resources?type=storage':
            return _Resp(200, [dict(s) for s in self.storages])
        m = re.fullmatch(r'/nodes/([^/]+)/network', path)
        if m:
            nets = self.networks.get(m.group(1))
            return _Resp(200, nets) if nets is not None else _Resp(500)
        table = {'/cluster/sdn/vnets': [{'vnet': v} for v in self.vnets],
                 '/cluster/ha/resources': self.ha_resources, '/cluster/ha/rules': self.ha_rules,
                 '/cluster/ha/groups': self.ha_groups, '/cluster/replication': self.replication}
        if path in table:
            return _Resp(200, table[path])
        return _Resp(404)

    # what a run calls
    def migrate_vm_manual(self, node, vmid, vm_type, target, online=True, options=None):
        with self.lock:
            self.started.append((vmid, target))
        return {'success': True, 'task': f'UPID:{node}:{vmid:08X}:00000001:6700AAAA:qmigrate:{vmid}:root@pam:'}

    def get_task_status(self, node, upid):
        return {'status': 'running', 'upid': upid}

    def get_tasks(self, limit=100):
        return []

    def get_vm_config(self, node, vmid, vm_type):
        return {'success': True, 'config': dict(self.configs.get(vmid) or {})}

    def remote_migrate_vm(self, *a, **kw):
        self.started.append(('remote',) + a)
        return {'success': True, 'task': 'UPID:pve1:1:qmigrate'}

    def create_api_token(self, name):
        self.tokens.append(name)
        return {'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}

    def delete_api_token(self, name):
        return {'success': True}

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': self.host, 'fingerprint': ':'.join(['AB'] * 32)}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    pf.reset_for_tests()
    for store in (xn._nets, xn._certs, xn._options):
        store.clear()
    for cid in (CID, TGT):
        clusters_api._health_storage_cache.invalidate(cid)
    bulk.reset_for_tests()
    # the backup age comes from the shared scan, which has not run here
    monkeypatch.setattr(pf, 'backup_times', lambda cid, mgr: None)
    yield
    for run in bulk.runs():
        bulk.cancel(run, 'teardown')
    bulk.reset_for_tests()
    pf.reset_for_tests()


def _rows(res):
    return {r['vmid']: r for r in res['guests']}


def _codes(row, level=None):
    return [r['code'] for r in row['reasons'] if level is None or r['level'] == level]


CFG = {'cpu': 'x86-64-v2-AES', 'scsi0': 'ceph:vm-disk-0,size=32G', 'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'}


# --- the verdicts --------------------------------------------------------------------------------

def test_a_guest_that_fits_is_ready_and_the_steps_say_how(api):
    _Pve(api, guests=[_guest(100)], configs={100: CFG})
    res = pf.intra(CID, api_mgr(), [100], 'pve2', mode='sequential')
    row = _rows(res)[100]
    assert row['verdict'] == 'ready' and row['to'] == 'pve2', row
    assert res['totals'] == {'guests': 1, 'ready': 1, 'warning': 0, 'blocked': 0, 'overridable': 0,
                             'overridden': 0, 'moving': 1}
    assert [s['kind'] for s in res['steps']] == ['run', 'recheck', 'migrate']
    assert res['steps'][2]['text'] == 'Migrate 100 (g100) from pve1 to pve2, live'
    assert 'keeps running on pve1' in row['abort']
    assert res['capacity'][0]['node'] == 'pve2' and res['capacity'][0]['mem_pct_after'] == 18.8


def api_mgr(cid=CID):
    from pegaprox.globals import cluster_managers
    return cluster_managers[cid]


def test_the_set_fills_the_target_and_the_last_one_does_not_fit(api):
    """Three guests of 26 GB onto a node with 56 GB free: the third is blocked, the first two
    count for it; each alone would fit"""
    _Pve(api, guests=[_guest(v, mem_gb=26) for v in (100, 101, 102)], configs={v: CFG for v in (100, 101, 102)})
    res = pf.intra(CID, api_mgr(), [100, 101, 102], 'pve2')
    rows = _rows(res)
    assert rows[100]['verdict'] == 'ready' and rows[101]['verdict'] == 'warning'
    assert _codes(rows[101]) == ['memory_tight']
    assert rows[102]['verdict'] == 'blocked' and rows[102]['overridable'] is True
    assert _codes(rows[102], 'blocked') == ['memory_short']
    # a check of 102 alone says it fits
    alone = _rows(pf.intra(CID, api_mgr(), [102], 'pve2'))[102]
    assert alone['verdict'] != 'blocked'


def test_what_proxmox_refuses_is_blocked_and_cannot_be_overridden(api):
    configs = {
        100: dict(CFG, lock='backup'),
        101: {'scsi0': 'local-lvm:vm-101-disk-0,size=16G', 'net0': 'virtio=x,bridge=vmbr0'},
        102: {'scsi0': 'local-lvm:vm-102-disk-0,size=16G', 'parent': 'snap1'},
        103: dict(CFG, net0='virtio=x,bridge=vmbr7'),
        104: dict(CFG, hostpci0='0000:01:00.0,pcie=1'),
        105: dict(CFG, ide2='local:iso/debian.iso,media=cdrom'),
        106: dict(CFG, scsi1='nfs-only:vm-106-disk-1,size=8G'),
    }
    guests = [_guest(v) for v in configs] + [_guest(107, status='running')]
    configs[107] = CFG
    stores = [_store(n, 'local-lvm') for n in ('pve1', 'pve2')] + [
        _store(n, 'ceph', shared=True, plugintype='rbd', content='images') for n in ('pve1', 'pve2')] + [
        _store('pve1', 'local', plugintype='dir', content='iso'), _store('pve2', 'local', plugintype='dir', content='iso'),
        _store('pve1', 'nfs-only', shared=True, plugintype='nfs')]
    m = _Pve(api, guests=guests, configs=configs, storages=stores,
             ha_resources=[{'sid': 'vm:107', 'state': 'started'}],
             ha_rules=[{'rule': 'pin', 'type': 'node-affinity', 'resources': 'vm:107', 'nodes': 'pve1,pve3',
                        'strict': 1}])
    res = pf.intra(CID, m, list(configs), 'pve2', online=True, with_local_disks=False)
    rows = _rows(res)
    expect = {100: 'locked', 101: 'local_disks', 102: 'snapshots_live', 103: 'bridge_missing',
              104: 'local_device', 105: 'local_cdrom', 106: 'storage_missing', 107: 'ha_node_rule'}
    for vmid, code in expect.items():
        assert rows[vmid]['verdict'] == 'blocked', (vmid, rows[vmid])
        assert code in _codes(rows[vmid], 'blocked'), (vmid, rows[vmid]['reasons'])
        assert rows[vmid]['overridable'] is False, vmid
    assert res['totals']['blocked'] == 8 and res['totals']['moving'] == 0
    assert all(s['kind'] in ('run', 'skip') for s in res['steps'])


def test_offline_the_snapshots_go_along_only_where_the_storage_keeps_them(api):
    configs = {100: {'scsi0': 'local-lvm:vm-100-disk-0,size=8G', 'parent': 's'},
               101: {'scsi0': 'local-zfs:vm-101-disk-0,size=8G', 'parent': 's'}}
    stores = [_store(n, 'local-lvm') for n in ('pve1', 'pve2')] + [
        _store(n, 'local-zfs', plugintype='zfspool') for n in ('pve1', 'pve2')]
    m = _Pve(api, guests=[_guest(100, status='stopped'), _guest(101, status='stopped')], configs=configs,
             storages=stores)
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2', online=False))
    assert 'snapshots_storage' in _codes(rows[100], 'blocked')
    assert rows[101]['verdict'] == 'ready' and 'local_disks' in _codes(rows[101], 'info')


def test_a_running_guest_on_an_offline_move_and_a_stopped_one_missing_a_bridge(api):
    configs = {100: CFG, 101: dict(CFG, net0='virtio=x,bridge=vmbr9'), 102: CFG}
    m = _Pve(api, guests=[_guest(100), _guest(101, status='stopped'), _guest(102, kind='lxc')], configs=configs)
    rows = _rows(pf.intra(CID, m, [100, 101, 102], 'pve2', online=False))
    assert 'running_offline' in _codes(rows[100], 'blocked')
    # stopped: it moves, and will not start there until the bridge exists
    assert rows[101]['verdict'] == 'warning' and _codes(rows[101], 'warning') == ['bridge_missing']
    assert 'running_offline' in _codes(rows[102], 'blocked')
    # a VNet of the same name counts as a bridge
    pf.reset_for_tests()
    m.vnets = ['vmbr9']
    assert _rows(pf.intra(CID, m, [101], 'pve2', online=False))[101]['verdict'] == 'ready'


def test_cpu_host_does_not_move_live_between_vendors(api):
    nodes = {'pve1': _node(model='Intel(R) Xeon(R) Gold 6230'), 'pve2': _node(model='AMD EPYC 7543'),
             'pve3': _node(model='Intel(R) Xeon(R) Silver 4210', cpus=2)}
    m = _Pve(api, guests=[_guest(100, cpus=4), _guest(101, status='stopped')], nodes=nodes,
             configs={100: dict(CFG, cpu='host'), 101: dict(CFG, cpu='host')})
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert 'cpu_vendor' in _codes(rows[100], 'blocked')
    # stopped, it boots with the CPU of the new node
    assert rows[101]['verdict'] == 'ready'
    rows = _rows(pf.intra(CID, m, [100], 'pve3'))
    # same vendor, another model: a warning; 4 vCPUs on a node of 2: a block
    assert 'cpu_model' in _codes(rows[100], 'warning') and 'vcpus' in _codes(rows[100], 'blocked')


def test_the_affinity_rules_are_judged_on_where_the_set_ends_up(api, monkeypatch):
    import pegaprox.api.history as history
    rules = [{'cluster_id': CID, 'enabled': True, 'enforce': True, 'type': 'together', 'name': 'web+db',
              'vms': [100, 101]}]
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [dict(r) for r in rules]})
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: CFG})
    # both go: together on pve2, nothing to say
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert rows[100]['verdict'] == 'ready' and rows[101]['verdict'] == 'ready'
    # one alone breaks the rule: blocked, and an enforced rule of PegaProx may be overridden
    row = _rows(pf.intra(CID, m, [100], 'pve2'))[100]
    assert _codes(row, 'blocked') == ['affinity'] and row['overridable'] is True
    assert row['reasons'][-1]['text'] == "Affinity rule 'web+db' keeps it off pve2"
    res = pf.intra(CID, m, [100], 'pve2', override={100})
    assert res['guests'][0]['overridden'] is True and res['totals']['moving'] == 1
    assert res['steps'][-1]['text'].endswith('a block overridden')


def test_proxmox_ha_rules_on_the_planned_placement(api):
    m = _Pve(api, guests=[_guest(100), _guest(101), _guest(102, node='pve2'), _guest(103)],
             configs={v: CFG for v in (100, 101, 102, 103)},
             ha_resources=[{'sid': f'vm:{v}', 'state': 'started'} for v in (100, 101, 102, 103)],
             ha_rules=[{'rule': 'apart', 'type': 'resource-affinity', 'affinity': 'negative',
                        'resources': 'vm:100,vm:102'},
                       {'rule': 'pair', 'type': 'resource-affinity', 'affinity': 'positive',
                        'resources': 'vm:101,vm:103'},
                       {'rule': 'pref', 'type': 'node-affinity', 'resources': 'vm:103', 'nodes': 'pve1:2,pve3:1'}])
    rows = _rows(pf.intra(CID, m, [100, 101], 'pve2'))
    assert 'ha_apart' in _codes(rows[100], 'blocked') and rows[100]['overridable'] is False
    assert 'ha_together' in _codes(rows[101], 'warning') and 'ha_managed' in _codes(rows[101], 'info')
    rows = _rows(pf.intra(CID, m, [101, 103], 'pve2'))
    assert 'ha_together' not in _codes(rows[101])
    assert 'ha_prefers' in _codes(rows[103], 'warning')
    assert 'through Proxmox HA' in next(s['text'] for s in pf.intra(CID, m, [101], 'pve2')['steps']
                                       if s['kind'] == 'migrate')


def test_replication_backups_and_the_busy_ones(api, monkeypatch):
    import time
    monkeypatch.setattr(pf, 'backup_times', lambda cid, mgr: {100: time.time() - 50 * 3600, 101: 0})
    m = _Pve(api, guests=[_guest(100), _guest(101), _guest(102), _guest(103, node='pve2')],
             configs={v: CFG for v in (100, 101, 102)}, backup_sla_max_age_hours=24,
             replication=[{'id': '100-0', 'guest': 100, 'target': 'pve2'}, {'id': '101-0', 'guest': 101,
                                                                           'target': 'pve3'}])
    res = pf.intra(CID, m, [100, 101, 102, 103], 'pve2', busy={102})
    rows = _rows(res)
    assert 'backup_old' in _codes(rows[100], 'warning') and 'replicated_to_target' in _codes(rows[100], 'info')
    assert 'no_backup' in _codes(rows[101], 'warning') and 'replication_follows' in _codes(rows[101], 'info')
    assert _codes(rows[102], 'blocked') == ['busy'] and _codes(rows[103], 'blocked') == ['already_there']
    # a backup is a warning, never a block
    assert rows[100]['verdict'] == rows[101]['verdict'] == 'warning'
    # the busy and the already-there are not read further
    assert sorted(m.config_reads) == [100, 101]


def test_auto_placement_takes_the_node_each_guest_fits_best(api):
    nodes = {'pve1': _node(), 'pve2': _node(mem_used_gb=50), 'pve3': _node(mem_used_gb=10),
             'pve4': _node(maintenance_mode=True)}
    nets = {'pve1': _net('vmbr0'), 'pve2': _net('vmbr0'), 'pve3': _net('vmbr0'), 'pve4': _net('vmbr0')}
    m = _Pve(api, guests=[_guest(100, mem_gb=8), _guest(101, mem_gb=8)], nodes=nodes, networks=nets,
             configs={100: CFG, 101: dict(CFG, net0='virtio=x,bridge=vmbr5')})
    nets['pve2'] = _net('vmbr0', 'vmbr5')
    rows = _rows(pf.intra(CID, m, [100, 101], None))
    # least memory in use after it, the node in maintenance out
    assert rows[100]['to'] == 'pve3'
    # only pve2 has its bridge
    assert rows[101]['to'] == 'pve2'


def test_reads_stay_bounded(api):
    """One storage list, one network read per target node and one config per guest,
    whatever the size of the set; a second check within the TTL reads no HA again"""
    vmids = list(range(100, 160))
    m = _Pve(api, guests=[_guest(v, mem_gb=0) for v in vmids], configs={v: CFG for v in vmids})
    pf.intra(CID, m, vmids, 'pve2')
    assert m.reads.count('/cluster/resources?type=storage') == 1
    assert [r for r in m.reads if r.endswith('/network')] == ['/nodes/pve2/network']
    assert sorted(m.config_reads) == vmids
    assert m.reads.count('/cluster/ha/resources') == 1
    pf.intra(CID, m, vmids, 'pve2')
    assert m.reads.count('/cluster/ha/resources') == 1 and m.reads.count('/cluster/replication') == 1


def test_a_read_that_fails_warns_and_blocks_nothing(api):
    m = _Pve(api, guests=[_guest(100)], configs={})
    m.storages = None
    m._api_get = lambda url, **kw: _Resp(500)
    row = _rows(pf.intra(CID, m, [100], 'pve2'))[100]
    assert row['verdict'] == 'warning' and _codes(row, 'warning') == ['config_unread']


# --- POST /api/clusters/<cid>/migration-preflight ------------------------------------------------

PF = f'/api/clusters/{CID}/migration-preflight'


def test_the_route_answers_the_preflight_and_changes_nothing(api, seed):
    m = _Pve(api, guests=[_guest(100), _guest(101, node='pve2')], configs={100: CFG})
    c = api.as_user(seed.user('root', role='admin'))
    before = seed.db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    r = c.post(PF, json={'vms': [{'vmid': 100}, 101], 'target': 'pve2', 'mode': 'parallel', 'parallel': 3})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['kind'] == 'intra' and body['totals']['ready'] == 1 and body['totals']['blocked'] == 1
    assert body['steps'][0]['text'].startswith('3 at a time')
    assert m.started == [] and bulk.runs() == []
    assert seed.db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


@pytest.mark.parametrize('body,error', [
    ({'vms': 100}, 'vms is a list of 1 to 1000 guests'),
    ({'vms': []}, 'vms is a list of 1 to 1000 guests'),
    ({'vms': list(range(1, 1002))}, 'vms is a list of 1 to 1000 guests'),
    ({'vms': [True]}, 'vms holds something that is no VMID'),
    ({'vms': [100], 'target': '../x'}, 'target is a node name'),
    ({'vms': [100], 'target': 5}, 'target is a node name'),
    ({'vms': [100], 'online': 'yes'}, 'online and with_local_disks are true or false'),
    ({'vms': [100], 'mode': 'fast'}, 'mode is sequential, parallel or all'),
    ({'vms': [100], 'mode': 'parallel', 'parallel': 9}, 'parallel is a number from 2 to 5'),
    ({'vms': [100], 'override': 'all'}, 'override is a list of VMIDs'),
    ({'vms': [100], 'override': [101]}, 'override names a guest this request does not move'),
])
def test_a_body_out_of_shape_is_a_400(api, seed, body, error):
    _Pve(api, guests=[_guest(100)], configs={100: CFG})
    r = api.as_user(seed.user('root', role='admin')).post(PF, json=body)
    assert r.status_code == 400 and r.get_json()['error'] == error, r.get_data(as_text=True)
    assert api.as_user(seed.user('root2', role='admin')).post(PF, data='[1]',
                                                               headers={'Content-Type': 'application/json'}).status_code == 400


def test_who_may_ask(api, seed):
    seed.tenant('globex', clusters=[TGT])
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: CFG})
    _Pve(api, cid=TGT)
    body = {'vms': [100], 'target': 'pve2'}
    assert api.anon().post(PF, json=body).status_code == 401
    for who in (seed.user('watcher', role='viewer'), seed.user('ops', role='user', denied=['vm.migrate'])):
        assert api.as_user(who).post(PF, json=body).status_code == 403, who['username']
    confined = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    other = seed.user('milton', role='user', tenant_id='globex')
    for who in (confined, other):
        assert api.as_user(who).post(PF, json=body).status_code == 403, who['username']
    # a VM-ACL user: their guest, without the node figures or the other guests; not another one
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = portal.post(PF, json=body)
    assert r.status_code == 200 and r.get_json()['scoped'] is True and r.get_json()['capacity'] == []
    r = portal.post(PF, json={'vms': [101], 'target': 'pve2'})
    assert r.status_code == 400 and r.get_json()['error'] == 'Not on this cluster or out of reach: 101'
    # counterproof: the admin and an operator of the cluster
    for who in (seed.user('root', role='admin'), seed.user('op', role='user', tenant_id='acme')):
        r = api.as_user(who).post(PF, json=body)
        assert r.status_code == 200 and r.get_json()['scoped'] is False, who['username']
    assert m.started == []


def test_a_scoped_caller_reads_no_other_guest_in_a_reason(api, seed, monkeypatch):
    import pegaprox.api.history as history
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [
        {'cluster_id': CID, 'enabled': True, 'enforce': False, 'type': 'separate', 'name': 'apart',
         'vms': [100, 555]}]})
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    _Pve(api, guests=[_guest(100), _guest(555, node='pve2')], configs={100: CFG},
         ha_resources=[{'sid': 'vm:100'}, {'sid': 'vm:555'}],
         ha_rules=[{'rule': 'r', 'type': 'resource-affinity', 'affinity': 'positive', 'resources': 'vm:100,vm:555'}])
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = portal.post(PF, json={'vms': [100], 'target': 'pve3'})
    assert r.status_code == 200
    assert '555' not in r.get_data(as_text=True)
    admin = api.as_user(seed.user('root', role='admin'))
    assert '555' in admin.post(PF, json={'vms': [100], 'target': 'pve3'}).get_data(as_text=True)


def test_a_scoped_caller_reads_no_node_figures(api, seed):
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    _Pve(api, guests=[_guest(100, mem_gb=200)], configs={100: CFG})
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    row = _rows(portal.post(PF, json={'vms': [100], 'target': 'pve2'}).get_json())[100]
    text = next(r['text'] for r in row['reasons'] if r['code'] == 'memory_short')
    assert text == 'pve2 runs out of memory with it (counting the guests before it in this set)'
    admin = api.as_user(seed.user('root', role='admin'))
    row = _rows(admin.post(PF, json={'vms': [100], 'target': 'pve2'}).get_json())[100]
    assert '208.0 GB of 64.0 GB' in next(r['text'] for r in row['reasons'] if r['code'] == 'memory_short')


def test_a_standby_answers_the_preflight_and_starts_no_dry_run(ha_env, seed):  # noqa: F811
    api = ha_env.api
    _Pve(api, guests=[_guest(100)], configs={100: CFG})
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post(PF, json={'vms': [100], 'target': 'pve2'})
    assert r.status_code == 200 and r.get_json()['totals']['ready'] == 1, r.get_data(as_text=True)
    r = c.post(f'/api/clusters/{CID}/vms/bulk-migrate', json={'vms': [100], 'target': 'pve2', 'dry_run': True})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


# --- bulk-migrate: the dry run and the run that consults the preflight ---------------------------

BM = f'/api/clusters/{CID}/vms/bulk-migrate'


def test_a_dry_run_starts_nothing_and_answers_the_plan(api, seed):
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: dict(CFG, lock='backup')})
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json={'vms': [100, 101], 'target': 'pve2', 'mode': 'sequential', 'dry_run': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['dry_run'] is True and body['steps'] == body['preflight']['steps']
    assert [s['kind'] for s in body['steps']] == ['run', 'recheck', 'migrate', 'skip']
    assert m.started == [] and bulk.runs() == [] and _audit('vm.bulk_migrated') == []
    # without a mode: all at once, as the call without one starts them
    r = c.post(BM, json={'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2', 'dry_run': True})
    assert r.status_code == 200 and r.get_json()['steps'][0]['text'].startswith('All at once')
    assert c.post(BM, json={'vms': [100], 'target': 'pve2', 'dry_run': 'yes'}).status_code == 400
    assert m.started == []


def test_the_run_skips_what_the_preflight_blocks(api, seed):
    m = _Pve(api, guests=[_guest(100), _guest(101), _guest(102, mem_gb=200)],
             configs={100: CFG, 101: dict(CFG, lock='backup'), 102: CFG})
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json={'vms': [100, 101, 102], 'target': 'pve2', 'mode': 'all'})
    assert r.status_code == 202, r.get_data(as_text=True)
    rows = {x['vmid']: (x['state'], x['note']) for x in r.get_json()['run']['rows']}
    assert rows[101] == ('skipped', 'It is locked (backup): Proxmox migrates no locked guest')
    assert rows[102][0] == 'skipped' and rows[102][1].startswith('pve2 runs out of memory')
    _wait_started(m, [100])
    assert _audit('vm.migrate_block_overridden') == []


def _wait_started(m, vmids, seconds=5):
    import time
    deadline = time.time() + seconds
    while time.time() < deadline and sorted(v for v, _t in m.started) != sorted(vmids):
        time.sleep(0.02)
    assert sorted(v for v, _t in m.started) == sorted(vmids)


def test_an_overridable_block_moves_when_overridden_and_confirmed(api, seed):
    m = _Pve(api, guests=[_guest(100, mem_gb=200), _guest(101)], configs={100: CFG, 101: dict(CFG, lock='backup')})
    c = api.as_user(seed.user('root', role='admin'))
    body = {'vms': [100, 101], 'target': 'pve2', 'mode': 'all', 'override': [100, 101]}
    r = c.post(BM, json=body)
    assert r.status_code == 400 and 'confirm_override' in r.get_json()['error']
    assert m.started == []
    r = c.post(BM, json=dict(body, confirm_override=True))
    assert r.status_code == 202, r.get_data(as_text=True)
    rows = {x['vmid']: x['state'] for x in r.get_json()['run']['rows']}
    # the lock is Proxmox's: no override moves it
    assert rows[101] == 'skipped'
    _wait_started(m, [100])
    (entry,) = _audit('vm.migrate_block_overridden')
    assert entry['user'] == 'root' and '100 (pve2 runs out of memory' in entry['details']
    assert '101 (' not in entry['details']


def test_the_call_without_a_mode_consults_the_preflight_too(api, seed):
    """Fails without the consult: the locked guest went to Proxmox, and a body without the
    node of a guest answered 500"""
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: dict(CFG, lock='backup')})
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(BM, json={'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'},
                                 {'vmid': 101, 'node': 'pve1', 'type': 'qemu'}], 'target': 'pve2'})
    assert r.status_code == 200
    res = {x['vmid']: x for x in r.get_json()['results']}
    assert res[100]['success'] is True
    assert res[101]['success'] is False and 'locked' in res[101]['error']
    assert m.started == [(100, 'pve2')]
    r = c.post(BM, json={'vms': [{'vmid': 100}], 'target': 'pve2'})
    assert r.status_code == 400 and r.get_json()['error'] == 'vms is a list of {vmid, node, type}'


# --- to another cluster ---------------------------------------------------------------------------

XPF = '/api/cross-cluster-migrate/preflight'
XC = '/api/cross-cluster-migrate'


def _two(api, src_guests=None, src_cfg=None, tgt_guests=(), **tgt):
    src = _Pve(api, cid=CID, guests=src_guests or [_guest(100), _guest(101, kind='lxc', status='stopped')],
               configs=src_cfg or {100: dict(CFG, scsi0='local-lvm:vm-100-disk-0,size=32G'),
                                   101: {'rootfs': 'local-lvm:vm-101-disk-0,size=8G',
                                         'net0': 'name=eth0,bridge=vmbr1'}})
    tgt.setdefault('nodes', {'far1': _node(model='Intel(R) Xeon(R) Gold 6230'), 'far2': _node(status='offline')})
    tgt.setdefault('storages', [_store('far1', 'fast', plugintype='zfspool'),
                                _store('far1', 'iso-only', plugintype='dir', content='iso')])
    tgt.setdefault('networks', {'far1': _net('vmbr0', 'vmbr2')})
    dst = _Pve(api, cid=TGT, guests=tgt_guests, name='far', **tgt)
    return src, dst


def _xbody(**kw):
    b = {'source_cluster': CID, 'target_cluster': TGT, 'vms': [100, 101], 'target_node': 'far1',
         'target_storage_map': {'local-lvm': 'fast'}, 'target_bridge_map': {'vmbr0': 'vmbr0', 'vmbr1': 'vmbr2'},
         'delete_source': False}
    b.update(kw)
    return b


def test_the_cross_cluster_preflight_checks_the_maps_and_the_target(api, seed):
    src, dst = _two(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post(XPF, json=_xbody())
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['kind'] == 'cross' and body['target_cluster'] == 'far'
    rows = _rows(body)
    assert rows[100]['verdict'] == 'ready' and rows[101]['verdict'] == 'ready', body['guests']
    assert [s['kind'] for s in body['steps']] == ['token', 'endpoint', 'migrate', 'migrate', 'source', 'cleanup']
    assert 'Migrate 100 (g100) live to far1 as VMID 100' == body['steps'][2]['text']
    assert 'half-copied guest 100 on far' in rows[100]['abort']
    # a storage that is not there, one that takes no disks, a bridge the node lacks
    r = c.post(XPF, json=_xbody(target_storage_map={'local-lvm': 'iso-only'}, target_bridge_map={'vmbr1': 'vmbr9'}))
    rows = _rows(r.get_json())
    assert 'storage_content' in _codes(rows[100], 'blocked')
    assert 'storage_content' in _codes(rows[101], 'blocked') and 'bridge_missing' in _codes(rows[101], 'blocked')
    assert 'bridge_unmapped' in _codes(rows[100], 'blocked')
    r = c.post(XPF, json=_xbody(target_storage_map={'local-lvm': 'gone'}))
    assert 'storage_missing' in _codes(_rows(r.get_json())[100], 'blocked')
    # an offline node, and a VMID taken there
    assert 'target_offline' in _codes(_rows(c.post(XPF, json=_xbody(target_node='far2')).get_json())[100])
    dst.guests[100] = _guest(100, node='far1')
    rows = _rows(c.post(XPF, json=_xbody()).get_json())
    assert 'vmid_taken' in _codes(rows[100], 'blocked') and rows[101]['verdict'] == 'ready'
    assert src.started == [] and dst.tokens == []


def test_a_cross_cluster_check_knows_the_tenant_and_who_may_delete(api, seed):
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID, TGT],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    src, dst = _two(api)
    u = api.as_user(seed.user('mover', role='user', tenant_id='ranged', denied=['vm.delete']))
    r = u.post(XPF, json=_xbody(vms=[100], delete_source=True))
    assert r.status_code == 200, r.get_data(as_text=True)
    row = _rows(r.get_json())[100]
    assert {'vmid_range', 'needs_delete'} <= set(_codes(row, 'blocked'))
    r = u.post(XPF, json=_xbody(vms=[100], target_vmid=1100))
    assert _rows(r.get_json())[100]['verdict'] == 'ready'


def test_who_may_ask_across_clusters(api, seed):
    seed.tenant('acme', clusters=[CID, TGT])
    seed.tenant('globex', clusters=['cluster_9'])
    seed.tenant('half', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal'])
    seed.vm_acl(TGT, 300, users=['halfway'])
    src, dst = _two(api)
    body = _xbody(vms=[100])
    assert api.anon().post(XPF, json=body).status_code == 401
    for who in (seed.user('watcher', role='viewer'), seed.user('ops', role='user', denied=['vm.migrate']),
                seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}}),
                seed.user('milton', role='user', tenant_id='globex')):
        assert api.as_user(who).post(XPF, json=body).status_code == 403, who['username']
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    assert portal.post(XPF, json=_xbody(vms=[101])).status_code == 403
    assert portal.post(XPF, json=body).status_code == 200
    # reaching the target through one guest is no standing to place one there
    halfway = api.as_user(seed.user('halfway', role='user', tenant_id='half'))
    r = halfway.post(XPF, json=body)
    assert r.status_code == 403 and 'target cluster' in r.get_json()['error']
    assert api.as_user(seed.user('root', role='admin')).post(XPF, json=body).status_code == 200
    assert src.started == [] and dst.tokens == []


@pytest.mark.parametrize('body,error', [
    ({'target_cluster': CID}, 'source_cluster and target_cluster are two different clusters'),
    ({'vms': 'x'}, 'vms is a list of 1 to 100 guests'),
    ({'vms': list(range(1, 102))}, 'vms is a list of 1 to 100 guests'),
    ({'vms': ['abc']}, 'vms holds something that is no VMID'),
    ({'target_node': None}, 'Target node is required for cross-cluster migration'),
    ({'vm_type': 'kvm'}, 'vm_type is qemu or lxc'),
    ({'target_vmid': 500}, 'target_vmid is one VMID, for a single guest'),
    ({'target_storage': 'a b'}, 'target_storage is a name'),
    ({'target_storage_map': {'local-lvm': 5}}, 'target_storage_map maps names to names'),
    ({'target_bridge_map': {'vmbr0': '../x'}}, 'target_bridge_map maps names to names'),
])
def test_a_cross_cluster_body_out_of_shape_is_a_400(api, seed, body, error):
    _two(api)
    r = api.as_user(seed.user('root', role='admin')).post(XPF, json=_xbody(**body))
    assert r.status_code == 400 and r.get_json()['error'] == error, r.get_data(as_text=True)


@pytest.fixture
def no_cleanup_thread(monkeypatch):
    import pegaprox.api.vms as vms
    import threading as _threading
    fake = types.SimpleNamespace(**{k: getattr(_threading, k) for k in dir(_threading) if not k.startswith('__')})
    fake.Thread = lambda *a, **k: types.SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(vms, 'threading', fake)


def _xrun(c, **kw):
    b = {'source_cluster': CID, 'target_cluster': TGT, 'vmid': 100, 'vm_type': 'qemu', 'source_node': 'pve1',
         'target_node': 'far1', 'target_storage_map': {'local-lvm': 'fast'}, 'delete_source': False}
    b.update(kw)
    return c.post(XC, json=b)


def test_the_cross_cluster_dry_run_mints_no_token(api, seed, no_cleanup_thread):
    src, dst = _two(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _xrun(c, dry_run=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['dry_run'] is True and r.get_json()['steps'][0]['kind'] == 'token'
    assert dst.tokens == [] and src.started == []


def test_a_cross_cluster_migration_the_preflight_blocks_does_not_start(api, seed, no_cleanup_thread):
    """Fails without the consult: the guest went to Proxmox with its VMID taken on the target"""
    src, dst = _two(api, tgt_guests=[_guest(100, node='far1')])
    c = api.as_user(seed.user('root', role='admin'))
    r = _xrun(c)
    assert r.status_code == 409 and 'VMID 100 is taken on far' in r.get_json()['error']
    assert dst.tokens == [] and src.started == []
    # not overridable: override changes nothing
    assert _xrun(c, override=[100], confirm_override=True).status_code == 409
    assert dst.tokens == []


def test_a_cross_cluster_override_is_confirmed_and_audited(api, seed, no_cleanup_thread):
    src, dst = _two(api, src_cfg={100: dict(CFG, scsi0='local-lvm:vm-100-disk-0,size=32G', parent='s1')})
    c = api.as_user(seed.user('root', role='admin'))
    r = _xrun(c)
    assert r.status_code == 409 and 'snapshots' in r.get_json()['error']
    assert _xrun(c, override=[100]).status_code == 400
    r = _xrun(c, override=[100], confirm_override=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['preflight']['verdict'] == 'blocked' and len(dst.tokens) == 1
    (entry,) = _audit('vm.migrate_block_overridden')
    assert 'Cross-cluster migration of qemu/100' in entry['details'] and 'snapshots' in entry['details']


def test_a_standby_answers_the_cross_cluster_preflight(ha_env, seed):  # noqa: F811
    api = ha_env.api
    _two(api)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    assert c.post(XPF, json=_xbody()).status_code == 200
    r = _xrun(c, dry_run=True)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


# --- what it shares with the rest -----------------------------------------------------------------

def test_the_dr_drill_and_the_migrate_check_take_their_rules_from_here():
    import pegaprox.api.dr_drill as drill
    import pegaprox.api.vms as vms
    import inspect
    assert vms._guest_volumes is pf.guest_volumes and vms._snapshot_family is pf.snapshot_family
    src = inspect.getsource(drill._execute_drill)
    assert 'cluster_bridges(' in src and 'storage_mapping_problems(' in src
    assert pf.storage_mapping_problems({'a': 'x', 'b': 'y', 'c': 'z'},
                                       {'x': {'content': 'images,rootdir'}, 'y': {'content': 'iso'}}) == [
        ('b', 'y', 'content'), ('c', 'z', 'missing')]


def test_the_cpu_vendor_comes_from_the_model_when_the_node_says_none():
    """Fails without it: PVE's node status names no vendor, so cpu:host between Intel and AMD
    nodes passed the balancer's check"""
    from pegaprox.core.manager import PegaProxManager as M
    v = M.cpu_verdict('host', {'model': 'Intel(R) Xeon(R) Gold 6230'}, {'model': 'AMD EPYC 7543'})
    assert v['compatible'] is False and 'vendor mismatch' in v['reason']
    assert M.cpu_verdict('host', {'model': 'A'}, {'model': 'A'})['compatible'] is True
    assert M.cpu_verdict('x86-64-v4', {}, {}, 'x86-64-v2-AES')['compatible'] is False


def test_the_preflight_routes_are_open_on_a_standby_and_nothing_else_new_is():
    import ast
    import inspect
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.create_app)).body[0]
    for node in ast.walk(fn):
        target = getattr(node, 'targets', [None])[0]
        if isinstance(node, ast.Assign) and getattr(target, 'id', '') == '_STANDBY_LOCAL_WRITES':
            local = set(ast.literal_eval(node.value.args[0]))
    assert {('POST', '/api/clusters/<cluster_id>/migration-preflight'),
            ('POST', '/api/cross-cluster-migrate/preflight')} <= local
    assert ('POST', '/api/clusters/<cluster_id>/vms/bulk-migrate') not in local
    assert ('POST', '/api/cross-cluster-migrate') not in local


def test_no_em_dash_in_the_new_module():
    import inspect
    text = inspect.getsource(pf)
    assert '\u2014' not in text and '\u2013' not in text
