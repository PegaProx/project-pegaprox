"""What a confined account reads of the cluster-wide views next to the node and datacenter
reads: balancing, HA, the what-if picker, resource mappings, the capacity forecast, the
datacenter options and the cross-cluster vnets.

A confined account (a VM-ACL user of the owning tenant, a pool user of another tenant, an
admin a tenant override lowers) sees the nodes its own guests run on and no more. These reads
still answered it as an operator: every running guest with its CPU, the forecast and the
address of every node, the HA rules with their guests, the HA setup with fallback hosts and
fences, the storages, bridges and vnets of every node, the devices of every node behind a
mapping, the usage trend of every storage, the whole datacenter options and the EVPN peers
and subnets of a cross-cluster vnet.

Now a confined caller
- is refused what no confined view needs, before the cluster is asked;
- gets the HA status, the what-if picker and the mappings of its guest with the nodes its
  guests run on only, the forecast with the cluster series only and the datacenter options
  with the MAC prefix only, which the NIC dialog of its guest makes addresses with;
- does not see a cross-cluster vnet on a cluster it is confined on.

An operator of the owning tenant and the admin get all of it, in the same test.
"""
import json
import time

import pytest

from pegaprox.core.manager import UnreadList
from test_node_and_storage_reads_confine_1218 import (  # noqa: F401  (fixtures)
    mgr, who, BASE, CID, CONFINED, WHOLE, THEIRS, _resp, _pool_member)

MARK = 'MARK-other-node'
REFUSED_WHOLE = 'affects the whole cluster'


def _pve(url, *a, **k):
    tail = url.split('/api2/json/', 1)[-1]
    if tail.endswith('apt/repositories'):
        return _resp(200, {'files': [{'path': '/etc/apt/sources.list', 'repositories': []}]})
    return _resp(200, [{'id': tail, 'tag': MARK}])


def _stub(mgr):
    mgr._create_session.return_value.get.side_effect = _pve
    mgr._api_get.side_effect = _pve
    mgr._get_cpu_compatibility_matrix.return_value = {
        'vms': [{'vmid': 200, 'name': 'other-app', 'node': 'n2', 'cpu_type': MARK}],
        'nodes': {'n2': {'model': MARK}}}
    mgr.get_predictive_analysis.return_value = {'n2': {'score': 1, 'tag': MARK}}
    mgr.config.predictive_balancing = False
    mgr.config.predictive_threshold = 75
    mgr.config.excluded_nodes = [MARK]
    mgr.config.fallback_hosts = [MARK]
    mgr.get_proxmox_ha_groups.return_value = [{'group': 'pin-other', 'nodes': 'n2:2,n1:1',
                                               '_pve_rule_resources': 'vm:200,vm:100', 'tag': MARK}]
    mgr.get_node_options.return_value = {'wakeonlan': 'aa:bb:cc:dd:ee:02', 'description': MARK}
    mgr.get_node_apt_updates.return_value = [{'Package': 'openssh-server', 'Title': MARK}]
    mgr.get_balancing_excluded_pools.return_value = []


# refused to a confined caller, also where its own guest runs (n1)
REFUSED = ['/cpu-compatibility', '/predictive-analysis', '/excluded-nodes', '/excluded-pools',
           '/fallback-hosts', '/proxmox-ha/groups', '/nodes/n1/options', '/nodes/n1/apt/updates',
           '/nodes/n1/repos']
# the stub hands these MARK, so the mirror can say the operator got the data itself
OPERATOR_SEES_MARK = set(REFUSED) - {'/excluded-pools', '/nodes/n1/repos'}


@pytest.mark.parametrize('path', REFUSED)
def test_a_confined_caller_is_refused_the_cluster_wide_reads(who, mgr, path):
    _stub(mgr)
    for kind in CONFINED:
        mgr.reset_mock()
        r = who[kind].get(BASE + path)
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and REFUSED_WHOLE in body, (kind, path, r.status_code, body[:200])
        assert MARK not in body and 'other-app' not in body
        # refused before the cluster is asked, the walk over every guest's config included
        assert not mgr._create_session.return_value.get.called and not mgr._api_get.called, (kind, path)
        asked = [c for c in mgr.method_calls if c[0] not in ('get_vm_resources',)]
        assert not asked, (kind, path, asked)
    for kind in WHOLE:
        r = who[kind].get(BASE + path)
        body = r.get_data(as_text=True)
        assert r.status_code == 200 and REFUSED_WHOLE not in body, (kind, path, r.status_code, body[:200])
        if path in OPERATOR_SEES_MARK:
            assert MARK in body, (kind, path, body[:200])


# reads behind a permission the shipped tenant templates grant (tenant_operator and tenant_admin
# carry node.maintenance and cluster.config): held by a confined account, they are still refused
WITH_PERMISSION = [('/nodes/n2/maintenance-preview', 'node.maintenance'),
                   ('/config/export', 'cluster.config'),
                   ('/nodes/n2/can-remove', 'cluster.admin')]


@pytest.mark.parametrize('path,perm', WITH_PERMISSION)
def test_a_confined_caller_holding_the_permission_is_refused_as_well(api, seed, mgr, path, perm):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('t_pool', clusters=[])
    seed.vm_acl(CID, 100, users=['portal_ops'])
    seed.pool(CID, 'pool1', 'pool_ops', ['vm.view'])
    _pool_member({'100:qemu': 'pool1'})
    mgr.maintenance_capacity_preview.return_value = {
        'ok': True, 'nodes': [{'node': 'n1', 'current_pct': 40, 'tag': MARK}], 'guest_count': 1}
    from pegaprox.models.tasks import PegaProxConfig
    mgr.config = PegaProxConfig({'name': CID, 'host': 'n1.example', 'user': 'root@pam'})
    mgr.nodes_in_maintenance = {}
    callers = {
        'acl_user': seed.user('portal_ops', role='user', tenant_id='acme', permissions=[perm]),
        'pool_user': seed.user('pool_ops', role='user', tenant_id='t_pool', permissions=[perm]),
    }
    for kind, u in callers.items():
        mgr.reset_mock()
        r = api.as_user(u).get(BASE + path)
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and REFUSED_WHOLE in body, (kind, path, r.status_code, body[:200])
        assert MARK not in body and 'root@pam' not in body
        assert not mgr.maintenance_capacity_preview.called
    ops = seed.user('ops_perm', role='user', tenant_id='acme', permissions=[perm])
    r = api.as_user(ops).get(BASE + path)
    assert r.status_code == 200 and REFUSED_WHOLE not in r.get_data(as_text=True), (path, r.status_code)


# --- PegaProx's HA status: the nodes of their guests --------------------------------------

def _pegaprox_ha():
    return {
        'enabled': True, 'check_interval': 10, 'failure_threshold': 3,
        'nodes': {n: {'status': 'online', 'last_seen': None, 'consecutive_failures': 0}
                  for n in ('n1', 'n2', 'n3')},
        'recovery_in_progress': ['n2', 'n1'],
        'fallback_hosts': ['10.9.9.2'],
        'split_brain_prevention': {'quorum_hosts': ['10.9.9.9'], 'storage_heartbeat_path': '/mnt/pve/hb',
                                   'fencing': {'n2': {'type': 'ipmi', 'host': '10.8.8.2', 'user': 'ipmi-admin'}}},
        'cluster_health': {'online_nodes': 3, 'total_nodes': 3},
        'discovered_storages': ['tank'], 'self_fence_nodes': ['n2'],
        'fence_agent': {'outdated': ['n2']}, 'cluster_claim': {'holder': 'pegaprox-a'},
        'interrupted_recoveries': [{'node': 'n2', 'moved': [200]}],
    }


@pytest.mark.parametrize('path', ['/ha', '/ha/status'])
def test_the_ha_status_carries_the_nodes_of_a_confined_callers_guests_only(who, mgr, path):
    mgr.get_ha_status.return_value = _pegaprox_ha()
    for kind in CONFINED:
        r = who[kind].get(BASE + path)
        assert r.status_code == 200, (kind, r.data)
        assert r.get_json() == {'enabled': True, 'check_interval': 10, 'failure_threshold': 3,
                                'nodes': {n: _pegaprox_ha()['nodes'][n] for n in sorted(THEIRS)},
                                'recovery_in_progress': ['n1']}, kind
        text = r.get_data(as_text=True)
        assert '10.9.9.2' not in text and '10.8.8.2' not in text and 'n2' not in text, kind
    for kind in WHOLE:
        assert who[kind].get(BASE + path).get_json() == _pegaprox_ha(), kind


def test_the_xcpng_ha_status_carries_the_guests_of_a_confined_caller_only(who, mgr):
    mgr.get_ha_status.return_value = {
        'enabled': True, 'host_failures_to_tolerate': 1, 'ha_statefiles': ['OpaqueRef:sf'],
        'protected_vms': [{'vmid': 100, 'name': 'portal-web', 'restart_priority': 'restart'},
                          {'vmid': 200, 'name': 'other-app', 'restart_priority': 'restart'}]}
    for kind in CONFINED:
        body = who[kind].get(f'{BASE}/ha/status').get_json()
        assert body == {'enabled': True, 'protected_vms': [
            {'vmid': 100, 'name': 'portal-web', 'restart_priority': 'restart'}]}, kind
    for kind in WHOLE:
        assert len(who[kind].get(f'{BASE}/ha/status').get_json()['protected_vms']) == 2


@pytest.mark.parametrize('kind', CONFINED)
def test_the_ha_status_says_so_when_a_confined_callers_guests_cannot_be_read(who, mgr, kind):
    mgr.get_ha_status.return_value = _pegaprox_ha()
    mgr.get_vm_resources.return_value = UnreadList()
    r = who[kind].get(f'{BASE}/ha/status')
    assert r.status_code == 503 and '10.9.9.2' not in r.get_data(as_text=True)
    assert not mgr.get_ha_status.called
    assert who['operator'].get(f'{BASE}/ha/status').status_code == 200


# --- the what-if picker: their nodes and what is on them --------------------------------------

def _whatif_options():
    return {
        'supported': True,
        'nodes': [{'name': n, 'status': 'online', 'maintenance': False} for n in ('n1', 'n2', 'n3')],
        'storages': [{'storage': 'local-lvm', 'type': 'lvmthin', 'nodes': ['n1', 'n2', 'n3'], 'shared': False},
                     {'storage': 'tank-' + MARK, 'type': 'zfspool', 'nodes': ['n2'], 'shared': False}],
        'pbs': [{'storage': 'pbs-' + MARK, 'nodes': ['n2']}, {'storage': 'pbs-all', 'nodes': ['n1', 'n2']}],
        'critical_tags': {'tags': ['prod'], 'source': 'default'},
        'bridges': [{'name': 'vmbr0', 'nodes': ['n1', 'n2'], 'vlan_aware': False},
                    {'name': 'vmbr9-' + MARK, 'nodes': ['n2'], 'vlan_aware': True}],
        'vnets': [{'vnet': 'tenantB', 'zone': 'z1', 'tag': 4242}],
        'ha': {'readable': True, 'resources': 3, 'pegaprox_ha': False},
    }


def test_the_whatif_picker_offers_a_confined_caller_its_nodes_and_what_is_on_them(who, mgr, monkeypatch):
    from pegaprox.core import whatif
    mgr.cluster_type = 'proxmox'
    monkeypatch.setattr(whatif, 'options', lambda m: _whatif_options())
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/whatif/options')
        assert r.status_code == 200, (kind, r.data)
        body = r.get_json()
        assert MARK not in r.get_data(as_text=True) and '"n2"' not in r.get_data(as_text=True), kind
        assert [n['name'] for n in body['nodes']] == ['n1', 'n3']
        assert body['storages'] == [{'storage': 'local-lvm', 'type': 'lvmthin', 'nodes': ['n1', 'n3'], 'shared': False}]
        assert body['pbs'] == [{'storage': 'pbs-all', 'nodes': ['n1']}]
        assert body['bridges'] == [{'name': 'vmbr0', 'nodes': ['n1'], 'vlan_aware': False}]
        # what the bridge list of their node offers them in the NIC dialog
        assert body['vnets'] == [{'vnet': 'tenantB', 'zone': 'z1', 'tag': 4242}]
        assert body['critical_tags'] == {'tags': ['prod'], 'source': 'default'} and 'thresholds' in body
    for kind in WHOLE:
        body = who[kind].get(f'{BASE}/whatif/options').get_json()
        assert {k: v for k, v in body.items() if k != 'thresholds'} == _whatif_options(), kind


def test_a_confined_caller_with_no_guest_on_a_node_is_offered_no_vnet(who, mgr, monkeypatch):
    from pegaprox.api import helpers
    from pegaprox.core import whatif
    mgr.cluster_type = 'proxmox'
    monkeypatch.setattr(whatif, 'options', lambda m: _whatif_options())
    _pool_member({})
    helpers.forget_node_scopes()
    body = who['pool_user'].get(f'{BASE}/whatif/options').get_json()
    assert body['nodes'] == body['storages'] == body['pbs'] == body['bridges'] == body['vnets'] == []


@pytest.mark.parametrize('kind', CONFINED)
def test_the_whatif_picker_says_so_when_a_confined_callers_guests_cannot_be_read(who, mgr, monkeypatch, kind):
    from pegaprox.core import whatif
    mgr.cluster_type = 'proxmox'
    asked = []
    monkeypatch.setattr(whatif, 'options', lambda m: asked.append(1) or _whatif_options())
    mgr.get_vm_resources.return_value = UnreadList()
    r = who[kind].get(f'{BASE}/whatif/options')
    assert r.status_code == 503 and MARK not in r.get_data(as_text=True)
    assert not asked


# --- the mappings of a guest's passthrough dialog: the devices of their nodes ---------------

def _mappings_pve(seen):
    def get(url, *a, params=None, **k):
        if 'cluster/mapping/pci' in url:
            seen.append((params or {}).get('check-node'))
            return _resp(200, [
                {'id': 'gpu-shared', 'description': 'GPU',
                 'map': ['node=n2,path=0000:81:00.0,id=10de:2204', 'node=n1,path=0000:01:00.0,id=10de:2204']},
                {'id': 'gpu-other', 'description': MARK, 'map': ['node=n2,path=0000:82:00.0,id=10de:2204']}])
        return _pve(url, *a, **k)
    return get


@pytest.mark.parametrize('url_node', ['n1', 'n2'])
def test_the_passthrough_mappings_of_a_confined_callers_guest_cover_its_nodes_only(who, mgr, url_node):
    seen = []
    mgr._create_session.return_value.get.side_effect = _mappings_pve(seen)
    mgr.pve_root_access.return_value = {'root': False}
    path = f'{BASE}/vms/{url_node}/qemu/100/passthrough/mappings?kind=pci'
    # the pool grant carries no vm.config, so the pool user is refused the route itself
    for kind in ('acl_user', 'lowered_admin'):
        seen.clear()
        r = who[kind].get(path)
        assert r.status_code == 200, (kind, r.data)
        text = r.get_data(as_text=True)
        assert '0000:81:00.0' not in text and MARK not in text and 'gpu-other' not in text, kind
        assert [(m['id'], m['nodes'], [e['path'] for e in m['entries']]) for m in r.get_json()['mappings']] == [
            ('gpu-shared', ['n1'], ['0000:01:00.0'])], kind
        # PVE checks a node of theirs only, never the one in the URL when it is not
        assert seen == (['n1'] if url_node == 'n1' else [None]), (kind, seen)
    for kind in WHOLE:
        seen.clear()
        body = who[kind].get(path).get_json()
        assert [m['id'] for m in body['mappings']] == ['gpu-other', 'gpu-shared'], kind
        assert seen == [url_node]


# --- the capacity forecast: the cluster series ------------------------------------------------

def _history():
    now = int(time.time())
    out = []
    for i in range(12):
        out.append((now - (12 - i) * 300, {
            'totals': {'cpu_total': 100, 'cpu_used': 20 + i, 'mem_total': 100, 'mem_used': 30 + i},
            'storage': {'tank-' + MARK: {'used': 50 + i, 'total': 100, 'pct': 50 + i}}}))
    return out


def test_the_forecast_of_a_confined_caller_has_the_cluster_series_only(who, mgr, monkeypatch):
    import pegaprox.api.insights as insights
    monkeypatch.setattr(insights, '_load_history', lambda cid, days=30: _history())
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/insights/forecast')
        assert r.status_code == 200, (kind, r.data)
        assert [f['metric'] for f in r.get_json()['forecasts']] == ['cluster_cpu', 'cluster_memory'], kind
        assert MARK not in r.get_data(as_text=True)
    for kind in WHOLE:
        got = who[kind].get(f'{BASE}/insights/forecast').get_json()
        assert [f['metric'] for f in got['forecasts']] == ['cluster_cpu', 'cluster_memory', 'tank-' + MARK], kind


# --- the datacenter options: the MAC prefix the NIC dialog makes addresses with ---------------

def _options_pve(options):
    def get(url, *a, **k):
        if url.endswith('cluster/options'):
            return _resp(200, options)
        return _pve(url, *a, **k)
    return get


def test_the_datacenter_options_hand_a_confined_caller_the_mac_prefix_only(who, mgr):
    full = {'mac_prefix': 'BC:24:11', 'keyboard': 'de', 'email_from': f'ops@{MARK}',
            'migration': 'type=secure,network=10.9.9.0/24', 'tag-style': 'shape=circle'}
    mgr._create_session.return_value.get.side_effect = _options_pve(full)
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/datacenter/options')
        assert r.status_code == 200 and r.get_json() == {'mac_prefix': 'BC:24:11'}, (kind, r.data)
    for kind in WHOLE:
        assert who[kind].get(f'{BASE}/datacenter/options').get_json() == full, kind
    mgr._create_session.return_value.get.side_effect = _options_pve({'keyboard': 'de', 'email_from': MARK})
    for kind in CONFINED:
        assert who[kind].get(f'{BASE}/datacenter/options').get_json() == {}, kind


# --- a cross-cluster vnet: not on a cluster the caller is confined on -------------------------

def _vnet(db):
    db.execute('INSERT INTO multi_cluster_vnets (id, name, zone, vni, asn, controller, peers, member_clusters, '
               'subnets, desired_state, status, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
               ('mv1', 'evpn1', 'evz', 5000, 65000, 'ctl1', '10.200.0.1,10.200.0.2', json.dumps([CID]),
                json.dumps([{'subnet': '10.50.0.0/24', 'gateway': '10.50.0.1'}]),
                json.dumps({'peers': '10.200.0.1,10.200.0.2'}), 'applied', 'ops', '2026-11-01'))


def test_a_cross_cluster_vnet_is_not_shown_to_a_caller_confined_on_a_member(who, mgr):
    from pegaprox.core.db import get_db
    _vnet(get_db())
    for kind in CONFINED:
        r = who[kind].get('/api/multi-sdn/vnets')
        assert r.status_code == 200 and r.get_json() == [], (kind, r.data)
        r = who[kind].get('/api/multi-sdn/vnets/mv1')
        assert r.status_code == 404 and '10.200.0.1' not in r.get_data(as_text=True), kind
    for kind in WHOLE:
        assert [v['id'] for v in who[kind].get('/api/multi-sdn/vnets').get_json()] == ['mv1'], kind
        r = who[kind].get('/api/multi-sdn/vnets/mv1')
        assert r.status_code == 200 and '10.200.0.1' in r.get_data(as_text=True), kind


# the dry run of a create, which reads the vnets and zones of every member, and the drift scan,
# which writes the snapshot everybody sees
SPAN_CALLS = {'validate': ('/api/multi-sdn/vnets/validate',
                           {'name': 'span2', 'zone': 'evz', 'vni': 5001, 'asn': 65000, 'controller': 'ctl1',
                            'peers': '10.200.0.1', 'cluster_ids': [CID]}),
              'scan': ('/api/multi-sdn/vnets/mv1/scan', None)}


@pytest.mark.parametrize('call', sorted(SPAN_CALLS))
def test_a_caller_confined_on_a_member_may_not_validate_or_scan_a_cross_cluster_vnet(api, seed, mgr, call):
    from pegaprox.core.db import get_db
    _vnet(get_db())
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 100, users=['portal_net'])
    perms = ['sdn.manage', 'admin.settings', 'node.view']
    confined = api.as_user(seed.user('portal_net', role='user', tenant_id='acme', permissions=perms))
    ops = api.as_user(seed.user('ops_net', role='user', tenant_id='acme', permissions=perms))
    mgr._api_get.return_value = _resp(200, [])
    path, payload = SPAN_CALLS[call]
    r = confined.post(path, json=payload)
    assert r.status_code == 403 and REFUSED_WHOLE in r.get_data(as_text=True), (path, r.status_code, r.data)
    assert not mgr._api_get.called
    r = ops.post(path, json=payload)
    assert r.status_code == 200 and REFUSED_WHOLE not in r.get_data(as_text=True), (path, r.status_code, r.data)
