"""The what-if simulator of a cluster (pegaprox/core/whatif.py, pegaprox/api/whatif.py).

A real PegaProxManager with its PVE reads answered from a dict, so the engine runs the code
the routes run: node failure under Proxmox HA rules and groups, quorum, PegaProx HA, the
maintenance evacuation, N+1 / N+2, a storage and a network failing, and the bound on guest
config reads. The routes are driven through the real app: who may run it, what a caller
confined to some guests sees, a standby, malformed bodies.
MK Oct 2026
"""
import logging
import time
import types

import pytest

from pegaprox.core import whatif
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig
from test_audit_bola_high_2026_09 import _seed_pool_membership
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

CID = 'cluster_1'
GiB = 1024 ** 3
NODES = ('pve1', 'pve2', 'pve3')
THR = {'cpu': 80.0, 'memory': 90.0}


def _resp(status=200, data=None):
    return types.SimpleNamespace(status_code=status, json=lambda: {'data': data}, text='')


def _vm(vmid, node, kind='qemu', status='running', mem=4, maxmem=8, cpu=0.5, maxcpu=4):
    return {'vmid': vmid, 'node': node, 'type': kind, 'status': status, 'mem': mem * GiB,
            'maxmem': maxmem * GiB, 'cpu': cpu, 'maxcpu': maxcpu, 'name': f'guest{vmid}'}


def _manager(api, vms, nodes=NODES, mem_used=16, mem_total=64, cores=16, maint=(), **config):
    """api: {path or (path, content kind) or ('/cluster/resources', 'storage'): data | response}"""
    m = object.__new__(PegaProxManager)
    m.id = CID
    m.logger = logging.getLogger('test.whatif')
    m.config = PegaProxConfig(dict({'name': 'lab', 'host': 'h', 'user': 'u'}, **config))
    m.current_host = None
    m.ha_enabled = False
    m.ha_config = {}
    m._rolling_update = None
    m.is_connected = True
    m.session = object()
    status = {n: {'status': 'online', 'maintenance_mode': n in maint, 'mem_used': mem_used * GiB,
                  'mem_total': mem_total * GiB, 'cpu_percent': 10.0, 'disk_percent': 10.0} for n in nodes}
    m.get_node_status = lambda: status
    m.get_vm_resources = lambda max_age=0: list(vms)
    m._cached_node_dict = {n: {'node': n, 'maxcpu': cores} for n in nodes}
    m._nodes_cache_time = time.time() + 3600
    m.calls = []

    def get(url, **kw):
        path = url.split('/api2/json', 1)[1]
        params = kw.get('params') or {}
        m.calls.append(path)
        key = (path, params['content']) if 'content' in params else path
        if params.get('type') == 'storage':
            key = ('/cluster/resources', 'storage')
        if key not in api:
            return _resp(404)
        v = api[key]
        return v if hasattr(v, 'status_code') else _resp(200, v)
    m._api_get = get
    return m


def _cfg(disk='ceph', bridge='vmbr0', tag=None, **extra):
    net = f'virtio=AA:BB:CC:00:00:01,bridge={bridge}' + (f',tag={tag}' if tag else '')
    return dict({'scsi0': f'{disk}:vm-1-disk-0,size=32G', 'net0': net, 'boot': 'order=scsi0'}, **extra)


STORAGES = [{'storage': 'ceph', 'type': 'rbd', 'shared': 1, 'content': 'images,rootdir'},
            {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir'},
            {'storage': 'backups', 'type': 'pbs', 'content': 'backup'}]


def _cluster(guests, configs, ha=(), rules=(), groups=None, extra=None):
    """The PVE answers: guests [(vm row)], configs {vmid: config}, ha [(sid, state[, group])]."""
    api = {
        '/cluster/ha/resources': [dict({'sid': s, 'state': st}, **({'group': g[0]} if g else {}))
                                  for s, st, *g in ha],
        '/cluster/ha/rules': list(rules) if groups is None else _resp(501),
        '/storage': STORAGES,
        ('/cluster/resources', 'storage'): [
            {'node': n, 'storage': s, 'status': 'available', 'shared': 1 if s == 'ceph' else 0}
            for n in NODES for s in ('ceph', 'local-lvm')],
    }
    if groups is not None:
        api['/cluster/ha/groups'] = groups
    for vm in guests:
        if vm['vmid'] in configs:
            api[f"/nodes/{vm['node']}/{vm['type']}/{vm['vmid']}/config"] = configs[vm['vmid']]
    api.update(extra or {})
    return api


def _run(m, **body):
    return whatif.run(m, whatif.parse_scenario(body), dict(THR))


def _rows(report):
    return {r['vmid']: r for r in report['guests']}


def _limit(report, code):
    return next((x for x in report['limits'] if x['code'] == code), None)


# --- node failure --------------------------------------------------------------------------------

def test_a_node_failure_restarts_what_ha_manages_and_leaves_the_rest_down():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve1'), _vm(103, 'pve1', 'lxc'),
              _vm(104, 'pve2'), _vm(105, 'pve1', status='stopped'), _vm(106, 'pve1')]
    configs = {100: _cfg(), 101: _cfg(), 102: _cfg('local-lvm'), 103: {'rootfs': 'ceph:vm-103-disk-0'},
               104: _cfg(), 106: _cfg(hostpci0='0000:01:00.0,pcie=1')}
    api = _cluster(guests, configs,
                   ha=[('vm:100', 'started'), ('vm:102', 'started'), ('ct:103', 'started'),
                       ('vm:104', 'started'), ('vm:106', 'started')],
                   rules=[{'rule': 'pin103', 'type': 'node-affinity', 'resources': 'ct:103', 'nodes': 'pve1', 'strict': 1},
                          {'rule': 'apart', 'type': 'resource-affinity', 'affinity': 'negative',
                           'resources': 'vm:100,vm:104'}])
    r = _run(_manager(api, guests), type='node_failure', nodes=['pve1'])
    rows = _rows(r)
    # the negative rule keeps 100 off pve2, where 104 runs
    assert rows[100]['outcome'] == 'restarted' and rows[100]['target'] == 'pve3'
    assert rows[100]['basis'] == 'known' and rows[100]['target_basis'] == 'assumed'
    assert rows[101]['outcome'] == 'down' and rows[101]['reason']['code'] == 'not_ha'
    assert rows[102]['reason']['code'] == 'local_disks' and rows[102]['reason']['args'] == {'node': 'pve1'}
    assert rows[103]['reason'] == {'code': 'no_node_rule', 'args': {'rule': 'pin103'}}
    assert rows[106]['reason']['code'] == 'passthrough' and rows[106]['basis'] == 'assumed'
    assert 105 not in rows and 104 not in rows          # stopped / on a node that stays up
    assert r['summary']['unaffected'] == 1 and r['summary']['down'] == 4
    assert _limit(r, 'not_ha')['guests'] == [101]
    assert _limit(r, 'local_disks')['args']['count'] == 1
    nodes = {n['node']: n for n in r['nodes']}
    assert nodes['pve1']['state'] == 'failed' and nodes['pve1']['mem_after'] is None
    # 8 GiB configured memory onto 16 of 64 GiB
    assert nodes['pve3']['mem_after'] == 37.5 and nodes['pve3']['guests_in'] == 1
    assert nodes['pve2']['mem_after'] == nodes['pve2']['mem_before'] == 25.0
    assert nodes['pve3']['basis'] == {'before': 'known', 'after': 'calculated'}
    codes = [a['code'] for a in r['assumptions']]
    for code in ('no_service_model', 'votes', 'ha_choice', 'mem_configured', 'cpu_now', 'fence_delay'):
        assert code in codes, codes


def test_the_memory_basis_can_be_what_the_guest_uses_now():
    guests = [_vm(100, 'pve1', mem=2, maxmem=8)]
    api = _cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')])
    r = _run(_manager(api, guests), type='node_failure', nodes=['pve1'], memory='current')
    pve2 = next(n for n in r['nodes'] if n['node'] == 'pve2')
    assert pve2['mem_after'] == pytest.approx(28.1, abs=0.1)   # 16 + 2 of 64 GiB
    assert 'mem_current' in [a['code'] for a in r['assumptions']]


def test_ha_picks_the_highest_priority_node_of_a_preferring_rule():
    guests = [_vm(100, 'pve1')]
    rules = [{'rule': 'pref', 'type': 'node-affinity', 'resources': 'vm:100', 'nodes': 'pve2:1,pve3:2', 'strict': 0}]
    api = _cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')], rules=rules)
    assert _rows(_run(_manager(api, guests), type='node_failure', nodes=['pve1']))[100]['target'] == 'pve3'
    # with pve3 down too the next priority, and with both down any node the rule does not forbid
    five = ('pve1', 'pve2', 'pve3', 'pve4', 'pve5')
    r = _run(_manager(api, guests, nodes=five), type='node_failure', nodes=['pve1', 'pve3'])
    assert _rows(r)[100]['target'] == 'pve2'
    r = _run(_manager(api, guests, nodes=five), type='node_failure', nodes=['pve2', 'pve3'][:1] + ['pve1'])
    assert _rows(r)[100]['target'] == 'pve3'


def test_a_restricted_pve8_group_is_a_hard_limit():
    guests = [_vm(100, 'pve1')]
    api = _cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started', 'g1')],
                   groups=[{'group': 'g1', 'nodes': 'pve1', 'restricted': 1}])
    row = _rows(_run(_manager(api, guests), type='node_failure', nodes=['pve1']))[100]
    assert row['outcome'] == 'down' and row['reason'] == {'code': 'no_node_rule', 'args': {'rule': 'g1'}}


def test_an_ignored_ha_resource_is_not_restarted():
    guests = [_vm(100, 'pve1')]
    api = _cluster(guests, {100: _cfg()}, ha=[('vm:100', 'ignored')])
    row = _rows(_run(_manager(api, guests), type='node_failure', nodes=['pve1']))[100]
    assert row['reason'] == {'code': 'ha_state', 'args': {'state': 'ignored'}}


def test_a_storage_limited_to_the_failed_node_keeps_the_guest_down():
    guests = [_vm(100, 'pve1')]
    api = _cluster(guests, {100: _cfg('nfs1')}, ha=[('vm:100', 'started')])
    api['/storage'] = STORAGES + [{'storage': 'nfs1', 'type': 'nfs', 'shared': 1, 'nodes': 'pve1', 'content': 'images'}]
    row = _rows(_run(_manager(api, guests), type='node_failure', nodes=['pve1']))[100]
    assert row['reason'] == {'code': 'no_node_storage', 'args': {'storages': ['nfs1']}}


def test_without_quorum_nothing_restarts_and_nodes_with_ha_guests_reset():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve3'), _vm(102, 'pve3')]
    api = _cluster(guests, {100: _cfg(), 101: _cfg(), 102: _cfg()},
                   ha=[('vm:100', 'started'), ('vm:101', 'started')])
    r = _run(_manager(api, guests), type='node_failure', nodes=['pve1', 'pve2'])
    rows = _rows(r)
    assert rows[100]['reason']['code'] == 'quorum_lost' and rows[100]['basis'] == 'calculated'
    # pve3 runs an HA guest: its watchdog resets it and the guest beside it goes too
    assert rows[101]['reason'] == {'code': 'fence_reset', 'args': {'node': 'pve3'}}
    assert rows[102]['reason']['code'] == 'fence_reset'
    assert _limit(r, 'quorum_lost')['args'] == {'left': 1, 'need': 2}
    assert _limit(r, 'fence_reset')['args']['nodes'] == ['pve3']
    assert next(n for n in r['nodes'] if n['node'] == 'pve3')['state'] == 'reset'


def test_a_qdevice_vote_keeps_a_two_node_cluster_quorate():
    guests = [_vm(100, 'pve1')]
    api = _cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')])
    m = _manager(api, guests, nodes=('pve1', 'pve2'))
    assert _rows(_run(m, type='node_failure', nodes=['pve1']))[100]['reason']['code'] == 'quorum_lost'
    m = _manager(api, guests, nodes=('pve1', 'pve2'))
    m.ha_config = {'fence_strategy': {'has_qdevice': True}}
    r = _run(m, type='node_failure', nodes=['pve1'])
    assert _rows(r)[100]['outcome'] == 'restarted'
    assert 'votes_qdevice' in [a['code'] for a in r['assumptions']]


def test_pegaprox_ha_restarts_running_guests_without_local_disks():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1')]
    api = _cluster(guests, {100: _cfg(), 101: _cfg('local-lvm')})
    m = _manager(api, guests)
    m.ha_enabled = True
    rows = _rows(_run(m, type='node_failure', nodes=['pve1']))
    assert rows[100]['outcome'] == 'restarted' and rows[100]['reason']['code'] == 'pegaprox_restart'
    assert rows[101]['reason']['code'] == 'local_disks'


def test_a_node_that_ends_up_overcommitted_degrades_its_guests():
    guests = [_vm(100, 'pve1', maxmem=40), _vm(101, 'pve2')]
    api = _cluster(guests, {100: _cfg(), 101: _cfg()}, ha=[('vm:100', 'started')])
    r = _run(_manager(api, guests, nodes=('pve1', 'pve2', 'pve3'), mem_used=30, mem_total=64), type='node_failure',
             nodes=['pve1', 'pve3'][:1])
    rows = _rows(r)
    hot = rows[100]['target']
    assert hot in ('pve2', 'pve3')
    assert _limit(r, 'overcommitted')['args']['nodes'] == [hot]
    assert rows[100]['risk'] == 'overcommitted'
    if hot == 'pve2':
        assert rows[101]['outcome'] == 'degraded' and rows[101]['reason']['code'] == 'overcommitted'


def test_unknown_or_offline_nodes_are_refused():
    m = _manager(_cluster([], {}), [])
    with pytest.raises(whatif.Invalid) as e:
        _run(m, type='node_failure', nodes=['nope'])
    assert e.value.code == 'unknown_node'
    m.get_node_status()['pve2']['status'] = 'offline'
    with pytest.raises(whatif.Invalid) as e:
        _run(m, type='node_failure', nodes=['pve2'])
    assert e.value.code == 'node_offline'


# --- maintenance ---------------------------------------------------------------------------------

def _maint_cluster(guests, configs, ha=(), rules=()):
    m = _manager(_cluster(guests, configs, ha=ha, rules=rules), guests)
    return m


def test_maintenance_moves_guests_as_the_evacuation_does():
    guests = [_vm(100, 'pve1', mem=8), _vm(101, 'pve1', mem=2), _vm(102, 'pve1'), _vm(103, 'pve1', 'lxc')]
    configs = {100: _cfg(), 101: _cfg(), 102: _cfg('local-lvm'), 103: {'rootfs': 'ceph:vm-103-disk-0'}}
    r = _run(_maint_cluster(guests, configs), type='maintenance', nodes=['pve1'])
    rows = _rows(r)
    assert rows[100]['outcome'] == 'moved' and rows[100]['reason']['code'] == 'moved_live'
    assert rows[100]['target_basis'] == 'calculated'
    assert rows[103]['outcome'] == 'restarted' and rows[103]['reason']['code'] == 'ct_restart'
    assert rows[102]['outcome'] == 'down' and rows[102]['reason']['code'] == 'local_disks_stay'
    # smallest first (101, then 103, then 100), each onto the node with the lowest score then
    assert [rows[v]['target'] for v in (101, 103, 100)] == ['pve2', 'pve3', 'pve2']
    pve1 = next(n for n in r['nodes'] if n['node'] == 'pve1')
    assert pve1['state'] == 'maintenance' and pve1['guests_out'] == 3
    assert 'maint_evacuator' in [a['code'] for a in r['assumptions']]
    # the option the maintenance dialog has: local disks are copied along
    rows = _rows(_run(_maint_cluster(guests, configs), type='maintenance', nodes=['pve1'], allow_local_disks=True))
    assert rows[102]['outcome'] == 'moved' and rows[102]['reason']['code'] == 'local_disks_copied'


def test_maintenance_follows_the_evacuation_placement_of_ha_rules():
    guests = [_vm(100, 'pve1')]
    rules = [{'rule': 'only1', 'type': 'node-affinity', 'resources': 'vm:100', 'nodes': 'pve1,pve3', 'strict': 1}]
    rows = _rows(_run(_maint_cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')], rules=rules),
                      type='maintenance', nodes=['pve1']))
    assert rows[100]['target'] == 'pve3'
    rows = _rows(_run(_maint_cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')], rules=rules),
                      type='maintenance', nodes=['pve1', 'pve3']))
    assert rows[100]['reason'] == {'code': 'no_node_rule', 'args': {'rule': 'only1'}}


def test_a_negative_rule_refuses_the_node_the_evacuation_picks_unless_it_gives_way():
    guests = [_vm(100, 'pve1'), _vm(104, 'pve2')]
    ha = [('vm:100', 'started'), ('vm:104', 'started')]
    rules = [{'rule': 'apart', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:100,vm:104'}]
    m = _maint_cluster(guests, {100: _cfg(), 104: _cfg()}, ha=ha, rules=rules)
    m.get_node_status()['pve3']['cpu_percent'] = 50.0     # the evacuation's choice is pve2
    r = _run(m, type='maintenance', nodes=['pve1'])
    assert _rows(r)[100]['reason'] == {'code': 'apart_refused', 'args': {'rule': 'apart', 'node': 'pve2'}}
    assert _limit(r, 'apart_refused')['guests'] == [100]
    m = _maint_cluster(guests, {100: _cfg(), 104: _cfg()}, ha=ha, rules=rules)
    m.get_node_status()['pve3']['cpu_percent'] = 50.0
    assert _rows(_run(m, type='maintenance', nodes=['pve1'], relax_anti_affinity=True))[100]['target'] == 'pve2'


def test_a_strict_pin_without_a_node_left_keeps_the_guest():
    guests = [dict(_vm(100, 'pve1'), tags='plb_pin_pve1')]
    m = _manager(_cluster(guests, {100: _cfg()}), guests, proxlb_tags_enabled=True, proxlb_pins_strict=True)
    r = _run(m, type='maintenance', nodes=['pve1'])
    assert _rows(r)[100]['reason'] == {'code': 'pin_strict', 'args': {'nodes': ['pve1']}}


def test_a_single_node_has_nowhere_to_evacuate_to():
    guests = [_vm(100, 'pve1')]
    m = _manager(_cluster(guests, {100: _cfg()}), guests, nodes=('pve1',))
    r = _run(m, type='maintenance', nodes=['pve1'])
    assert _rows(r)[100]['reason']['code'] == 'no_target'
    assert _limit(r, 'no_target')['guests'] == [100]


# --- N+1 / N+2 -----------------------------------------------------------------------------------

def test_headroom_names_the_failure_that_overloads_the_rest():
    # pve1 carries far more than the others could take
    guests = [_vm(100 + i, 'pve1', maxmem=20) for i in range(5)] + [_vm(200, 'pve2'), _vm(300, 'pve3')]
    m = _manager(_cluster(guests, {}), guests)
    r = _run(m, type='headroom', depth=1)
    h = r['headroom']
    assert h['depth'] == 1 and h['checked'] == 3 and not h['ok']
    worst = h['combinations'][0]
    assert worst['failed'] == ['pve1'] and not worst['ok'] and worst['over_mem']
    assert worst['basis'] == 'calculated' and worst['checked'] == 'placed'
    others = [c for c in h['combinations'] if c['failed'] != ['pve1']]
    assert all(c['ok'] for c in others)
    assert r['guests'] == [] and m.calls.count('/nodes/pve1/qemu/100/config') == 0   # no config reads
    nodes = {n['node']: n for n in r['nodes']}
    assert nodes['pve2']['worst_when'] == ['pve1'] or nodes['pve3']['worst_when'] == ['pve1']
    assert 'headroom_all' in [a['code'] for a in r['assumptions']]


def test_headroom_with_only_ha_guests_moves_less():
    guests = [_vm(100 + i, 'pve1', maxmem=20) for i in range(5)]
    m = _manager(_cluster(guests, {}, ha=[('vm:100', 'started')]), guests)
    combo = next(c for c in _run(m, type='headroom', guests='ha')['headroom']['combinations'] if c['failed'] == ['pve1'])
    assert combo['guests'] == 1 and combo['ok']


def test_n_plus_2_places_the_heaviest_pairs_and_sums_up_the_rest(monkeypatch):
    monkeypatch.setattr(whatif, 'PAIRS_PLACED', 2)
    nodes = ('pve1', 'pve2', 'pve3', 'pve4', 'pve5')
    guests = [_vm(100 + i, n) for i, n in enumerate(nodes)]
    m = _manager(_cluster(guests, {}), guests, nodes=nodes)
    h = _run(m, type='headroom', depth=2)['headroom']
    assert h['checked'] == 10
    assert sorted(c['checked'] for c in h['combinations']).count('placed') == 2
    assert all(c['quorate'] for c in h['combinations'])    # 3 of 5 votes stay
    r = _run(_manager(_cluster(guests, {}), guests, nodes=nodes), type='headroom', depth=2)
    assert next(a for a in r['assumptions'] if a['code'] == 'headroom_pairs')['args'] == {'placed': 2, 'total': 10}


def test_n_plus_2_on_three_nodes_loses_quorum():
    guests = [_vm(100, 'pve1')]
    h = _run(_manager(_cluster(guests, {}), guests), type='headroom', depth=2)['headroom']
    assert h['checked'] == 3 and h['failing'] == 3 and not any(c['quorate'] for c in h['combinations'])


# --- storage -------------------------------------------------------------------------------------

def test_a_local_storage_failing_on_one_node():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve1'), _vm(103, 'pve2'), _vm(104, 'pve1', status='stopped')]
    configs = {100: _cfg('local-lvm'), 101: _cfg(scsi1='local-lvm:vm-101-disk-1'), 102: _cfg(unused0='local-lvm:vm-102-disk-9'),
               103: _cfg('local-lvm')}
    content = [{'volid': f'local-lvm:vm-{v}-disk-0', 'vmid': v} for v in (100, 101, 102, 103, 104)]
    api = _cluster(guests, configs, extra={('/nodes/pve1/storage/local-lvm/content', 'images'): content,
                                           ('/nodes/pve1/storage/local-lvm/content', 'rootdir'): []})
    r = _run(_manager(api, guests), type='storage_failure', storage='local-lvm', node='pve1')
    rows = _rows(r)
    assert rows[100]['outcome'] == 'down' and rows[100]['reason'] == {
        'code': 'disk_on_storage', 'args': {'disk': 'scsi0', 'storage': 'local-lvm'}}
    assert rows[101]['outcome'] == 'degraded' and rows[101]['reason']['args']['disk'] == 'scsi1'
    assert 102 not in rows      # only an unused disk there
    # 103 runs on pve2: what pve1 holds of it is a copy (replication)
    assert rows[103]['outcome'] == 'degraded' and rows[103]['reason']['code'] == 'copy_on_storage'
    assert rows[103]['basis'] == 'assumed'
    assert r['stopped_affected'] == 1
    assert r['storage'] == {'storage': 'local-lvm', 'shared': False, 'nodes': ['pve1'], 'type': 'lvmthin'}
    assert _limit(r, 'no_ha_reaction')['basis'] == 'known'
    # nothing moves: before and after are the same
    assert all(n['mem_after'] == n['mem_before'] for n in r['nodes'])


def test_a_shared_storage_is_read_once_for_all_nodes():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve3')]
    content = [{'volid': 'ceph:vm-100-disk-0', 'vmid': 100}, {'volid': 'ceph:vm-101-disk-0', 'vmid': 101}]
    api = _cluster(guests, {100: _cfg(), 101: _cfg()},
                   extra={('/nodes/pve1/storage/ceph/content', 'images'): content,
                          ('/nodes/pve1/storage/ceph/content', 'rootdir'): []})
    m = _manager(api, guests)
    r = _run(m, type='storage_failure', storage='ceph')
    assert {v: x['outcome'] for v, x in _rows(r).items()} == {100: 'down', 101: 'down'}
    assert [c for c in m.calls if c.endswith('/content')] == ['/nodes/pve1/storage/ceph/content'] * 2


def test_an_unknown_storage_or_one_not_on_the_node_is_refused():
    m = _manager(_cluster([], {}), [])
    with pytest.raises(whatif.Invalid) as e:
        _run(m, type='storage_failure', storage='nope')
    assert e.value.code == 'unknown_storage'
    api = _cluster([], {})
    api[('/cluster/resources', 'storage')] = [{'node': 'pve1', 'storage': 'local-lvm', 'status': 'available'}]
    with pytest.raises(whatif.Invalid) as e:
        _run(_manager(api, []), type='storage_failure', storage='local-lvm', node='pve2')
    assert e.value.code == 'storage_not_on_node'


# --- network -------------------------------------------------------------------------------------

NETS = {'/nodes/pve1/network': [{'iface': 'vmbr0', 'type': 'bridge', 'bridge_vlan_aware': 1},
                                {'iface': 'vmbr1', 'type': 'bridge'}],
        '/nodes/pve2/network': [{'iface': 'vmbr0', 'type': 'bridge'}],
        '/nodes/pve3/network': [{'iface': 'vmbr0', 'type': 'bridge'}],
        '/cluster/sdn/vnets': [{'vnet': 'v20', 'zone': 'z1', 'tag': 20}, {'vnet': 'v30', 'zone': 'z1', 'tag': 30},
                               {'vnet': 'vx', 'zone': 'evpn1'}],
        '/cluster/sdn/zones': [{'zone': 'z1', 'type': 'vlan', 'bridge': 'vmbr0'}, {'zone': 'evpn1', 'type': 'evpn'}]}


def test_a_vlan_failing_on_a_bridge_of_one_node():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve1'), _vm(103, 'pve1'), _vm(104, 'pve2')]
    configs = {100: _cfg(tag=20), 101: _cfg(tag=30), 102: _cfg(bridge='v20', net1='virtio=AA,bridge=vmbr1'),
               103: _cfg(bridge='v30'), 104: _cfg(tag=20)}
    m = _manager(_cluster(guests, configs, extra=NETS), guests)
    r = _run(m, type='network_failure', bridge='vmbr0', vlan=20, node='pve1')
    rows = _rows(r)
    assert rows[100]['outcome'] == 'down' and rows[100]['reason'] == {'code': 'all_nics', 'args': {'nets': ['vmbr0.20']}}
    assert 101 not in rows and 103 not in rows and 104 not in rows
    # v20 is a VNet of a VLAN zone on vmbr0 with tag 20: it goes down with it
    assert rows[102]['outcome'] == 'degraded' and rows[102]['reason']['args'] == {'nics': ['net0'], 'nets': ['v20']}
    assert r['network']['sdn_vnets'] == ['v20']
    # only the node's own guests are read
    assert '/nodes/pve2/qemu/104/config' not in m.calls
    assert {'net_down', 'net_underlay'} <= {a['code'] for a in r['assumptions']}


def test_a_vnet_failing_everywhere():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve2')]
    m = _manager(_cluster(guests, {100: _cfg(bridge='vx'), 101: _cfg()}, extra=NETS), guests)
    rows = _rows(_run(m, type='network_failure', vnet='vx'))
    assert list(rows) == [100] and rows[100]['outcome'] == 'down'
    with pytest.raises(whatif.Invalid) as e:
        _run(m, type='network_failure', vnet='nope')
    assert e.value.code == 'unknown_vnet'
    with pytest.raises(whatif.Invalid) as e:
        _run(m, type='network_failure', bridge='vmbr9')
    assert e.value.code == 'unknown_bridge'


# --- bounded reads -------------------------------------------------------------------------------

def test_config_reads_are_bounded_per_run_and_kept_for_the_next(monkeypatch):
    monkeypatch.setattr(whatif, 'CONFIG_READS', 3)
    guests = [_vm(100 + i, 'pve1') for i in range(5)]
    m = _manager(_cluster(guests, {100 + i: _cfg() for i in range(5)}, extra=NETS), guests)
    r = _run(m, type='network_failure', bridge='vmbr0')
    assert r['reads'] == {'configs_read': 3, 'configs_cached': 0, 'configs_unread': 2}
    assert r['summary']['down'] == 3 and r['summary']['unknown'] == 2
    assert _rows(r)[104]['reason']['code'] == 'config_unread'
    assert _limit(r, 'configs_unread')['args'] == {'count': 2}
    assert next(a for a in r['assumptions'] if a['code'] == 'configs_unread')['args'] == {'count': 2}
    reads = len([c for c in m.calls if c.endswith('/config')])
    r = _run(m, type='network_failure', bridge='vmbr0')
    assert r['reads'] == {'configs_read': 2, 'configs_cached': 3, 'configs_unread': 0}
    assert len([c for c in m.calls if c.endswith('/config')]) == reads + 2


def test_the_cluster_configuration_is_read_once_a_minute():
    guests = [_vm(100, 'pve1')]
    m = _manager(_cluster(guests, {100: _cfg()}, ha=[('vm:100', 'started')]), guests)
    _run(m, type='node_failure', nodes=['pve1'])
    _run(m, type='node_failure', nodes=['pve1'])
    assert m.calls.count('/cluster/ha/resources') == 1 and m.calls.count('/storage') == 1


def test_an_unreadable_guest_list_is_no_empty_cluster():
    from pegaprox.core.manager import UnreadList
    m = _manager(_cluster([], {}), [])
    m.get_vm_resources = lambda max_age=0: UnreadList()
    with pytest.raises(whatif.Unreadable):
        _run(m, type='headroom')


# --- the scenario a request names ---------------------------------------------------------------

@pytest.mark.parametrize('body', [
    None, [], 'x', {}, {'type': 'meteor'}, {'type': 'node_failure'}, {'type': 'node_failure', 'nodes': []},
    {'type': 'node_failure', 'nodes': 'pve1'}, {'type': 'node_failure', 'nodes': ['../etc']},
    {'type': 'node_failure', 'nodes': [f'n{i}' for i in range(17)]},
    {'type': 'maintenance', 'nodes': ['pve1'], 'allow_local_disks': 'yes'},
    {'type': 'headroom', 'depth': 3}, {'type': 'headroom', 'depth': True}, {'type': 'headroom', 'guests': 'some'},
    {'type': 'storage_failure'}, {'type': 'storage_failure', 'storage': 'a b'},
    {'type': 'network_failure'}, {'type': 'network_failure', 'bridge': 'vmbr0', 'vlan': 0},
    {'type': 'network_failure', 'bridge': 'vmbr0', 'vlan': '20'},
    {'type': 'headroom', 'memory': 'all'}, {'type': 'headroom', 'thresholds': {'cpu': 0}},
    {'type': 'headroom', 'thresholds': {'disk': 50}}, {'type': 'headroom', 'thresholds': {'cpu': True}},
])
def test_a_malformed_scenario_is_refused(body):
    with pytest.raises(whatif.Invalid):
        whatif.parse_scenario(body)


def test_a_scenario_is_normalized():
    assert whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1', 'pve1', 'pve2']}) == {
        'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1', 'pve2']}
    assert whatif.parse_scenario({'type': 'network_failure', 'bridge': 'vmbr0', 'vlan': 20, 'node': '',
                                  'thresholds': {'cpu': 70}})['thresholds'] == {'cpu': 70.0}


def test_every_code_has_its_english():
    import re
    src = open(whatif.__file__, encoding='utf-8').read()
    for code in set(re.findall(r"run\.guest\([^,]+, '\w+', '(\w+)'", src)):
        assert code in whatif.REASONS, code
    for code in set(re.findall(r"run\.limit\('(\w+)'", src)):
        assert code in whatif.LIMITS, code
    for code in set(re.findall(r"run\.assume\('(\w+)'", src)):
        assert code in whatif.ASSUMPTIONS, code


# --- routes --------------------------------------------------------------------------------------

def _route_cluster():
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve2')]
    api = _cluster(guests, {100: _cfg(), 101: _cfg(), 102: _cfg()}, ha=[('vm:100', 'started')], extra=NETS)
    return guests, api


@pytest.fixture
def env(api, seed):
    guests, pve = _route_cluster()
    m = api.set_manager(CID, _manager(pve, guests))
    return types.SimpleNamespace(api=api, seed=seed, mgr=m)


URL = f'/api/clusters/{CID}/whatif'


def test_an_admin_runs_a_scenario(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    r = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']})
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert {g['vmid']: g['outcome'] for g in d['guests']} == {100: 'restarted', 101: 'down'}
    assert d['guests_hidden'] == 0 and d['guests_truncated'] == 0
    assert d['thresholds'] == {'cpu': 80.0, 'memory': 90.0, 'cpu_source': 'default', 'memory_source': 'default'}
    o = c.get(URL + '/options')
    assert o.status_code == 200
    od = o.get_json()
    assert [n['name'] for n in od['nodes']] == list(NODES)
    assert [s['storage'] for s in od['storages']] == ['ceph', 'local-lvm']     # no backup-only storage
    assert [b['name'] for b in od['bridges']] == ['vmbr0', 'vmbr1']
    assert [v['vnet'] for v in od['vnets']] == ['v20', 'v30', 'vx']
    assert od['thresholds']['cpu_source'] == 'default'


def test_the_thresholds_come_from_the_alert_rules_and_a_run_may_set_its_own(env):
    from pegaprox.api.alerts import save_cluster_alerts
    save_cluster_alerts({CID: [
        {'id': 'a1', 'cluster_id': CID, 'metric': 'memory', 'operator': '>', 'threshold': 85, 'target_type': 'cluster',
         'enabled': True},
        {'id': 'a2', 'cluster_id': CID, 'metric': 'memory', 'operator': '>', 'threshold': 75, 'target_type': 'node',
         'target_id': 'pve2', 'enabled': True},
        {'id': 'a3', 'cluster_id': CID, 'metric': 'cpu', 'operator': '>', 'threshold': 50, 'target_type': 'cluster',
         'enabled': False},
    ]})
    c = env.api.as_user(env.seed.user('root', role='admin'))
    d = c.post(URL, json={'type': 'headroom'}).get_json()
    assert d['thresholds'] == {'cpu': 80.0, 'memory': 85.0, 'cpu_source': 'default', 'memory_source': 'alert_rule'}
    nodes = {n['node']: n for n in d['nodes']}
    assert nodes['pve2']['mem_threshold'] == 75.0 and nodes['pve1']['mem_threshold'] == 85.0
    d = c.post(URL, json={'type': 'headroom', 'thresholds': {'memory': 95}}).get_json()
    assert d['thresholds']['memory'] == 95.0 and d['thresholds']['memory_source'] == 'request'
    assert {n['node']: n['mem_threshold'] for n in d['nodes']} == {'pve1': 95.0, 'pve2': 95.0, 'pve3': 95.0}


@pytest.mark.parametrize('body,code', [
    ('not json', 'bad_body'), ({'type': 'nope'}, 'bad_type'),
    ({'type': 'node_failure', 'nodes': ['pve9']}, 'unknown_node'),
    ({'type': 'storage_failure', 'storage': 'nope'}, 'unknown_storage'),
    ({'type': 'network_failure', 'bridge': 'vmbr0', 'vlan': 5000}, 'bad_vlan'),
])
def test_a_malformed_body_is_a_400(env, body, code):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    r = c.post(URL, data=body, content_type='application/json') if isinstance(body, str) else c.post(URL, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['code'] == code


@pytest.mark.parametrize('who', ['no-cluster-view', 'confined-admin', 'other-tenant'])
def test_who_may_not_run_it(env, who):
    seed = env.seed
    if who == 'no-cluster-view':
        user = seed.user('nora', role='viewer', denied=['cluster.view'])
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    else:
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme')
    c = env.api.as_user(user)
    assert c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']}).status_code == 403
    assert c.get(URL + '/options').status_code == 403


def test_a_viewer_runs_it(env):
    c = env.api.as_user(env.seed.user('vicky', role='viewer'))
    r = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']})
    assert r.status_code == 200 and len(r.get_json()['guests']) == 2


def test_a_pool_scoped_caller_sees_its_guests_and_the_counts(env):
    seed = env.seed
    seed.tenant('acme', clusters=[CID])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {101: ('qemu', 'pool_1')})
    c = env.api.as_user(seed.user('mallory', role='viewer', tenant_id='acme'))
    d = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']}).get_json()
    assert [g['vmid'] for g in d['guests']] == [101]
    assert d['guests_hidden'] == 1
    assert d['summary']['down'] == 1 and d['summary']['restarted'] == 1      # counts stay whole
    assert _limit(d, 'not_ha')['guests'] == [101]
    assert 'guest100' not in str(d)


def test_the_rows_are_cut_after_the_limit(env, monkeypatch):
    import pegaprox.api.whatif as route
    monkeypatch.setattr(route, 'GUEST_ROWS', 1)
    c = env.api.as_user(env.seed.user('root', role='admin'))
    d = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']}).get_json()
    assert len(d['guests']) == 1 and d['guests_truncated'] == 1 and d['summary']['down'] == 1


def test_an_xcpng_pool_and_a_disconnected_cluster(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    env.mgr.cluster_type = 'xcpng'
    assert c.post(URL, json={'type': 'headroom'}).get_json() == {'supported': False}
    env.mgr.cluster_type = 'proxmox'
    env.mgr.is_connected = False
    assert c.post(URL, json={'type': 'headroom'}).status_code == 503
    assert c.post('/api/clusters/nope/whatif', json={'type': 'headroom'}).status_code in (403, 404)


def test_a_standby_runs_it_from_its_own_view(ha_env, seed):  # noqa: F811
    guests, pve = _route_cluster()
    ha_env.api.set_manager(CID, _manager(pve, guests))
    c = ha_env.api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(r.get_json()['guests']) == 2
    # a write next to it is still refused there
    r = c.post(f'/api/clusters/{CID}/nodes/pve1/maintenance', json={})
    assert r.status_code in (404, 405, 409)


def test_the_route_is_in_the_api_reference():
    import json
    import os
    spec = json.load(open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'openapi.json')))
    assert '/api/clusters/{cluster_id}/whatif' in spec['paths']
    assert '/api/clusters/{cluster_id}/whatif/options' in spec['paths']
