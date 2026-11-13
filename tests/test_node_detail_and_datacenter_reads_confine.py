"""What a confined account reads of a node's details, of the datacenter, of the cluster's
networks and of the HA manager.

The node lists of a confined account (a VM-ACL user of the owning tenant, a pool user of
another tenant, an admin a tenant override lowers) were cut to the nodes its own guests run
on, but the detail reads were still answered as for an operator: the disks of any node with
their serials, SMART, LVM and ZFS, its network configuration, DNS, hosts file, certificates
and subscription key, the datacenter firewall and SDN, and every guest of the cluster in
/networks and in the HA manager status.

Now a confined caller
- is refused the host details and the whole-cluster datacenter reads before the cluster is
  asked, on the node of its own guest too;
- reads what the node page and its guest dialogs need (summary, charts, time, the bridge
  list with the SDN vnets, ISOs, PCI and USB devices) on the nodes its guests run on only;
- gets /networks and the HA manager status with the guests it may see and the nodes those
  run on, cut from copies of what the manager answers to everyone.

An operator of the owning tenant and the admin get all of it, in the same test.
"""
import copy
import inspect
import time

import pytest

from pegaprox.core.manager import UnreadList
from test_node_and_storage_reads_confine_1218 import (  # noqa: F401  (fixtures)
    mgr, who, BASE, CONFINED, WHOLE, THEIRS, _resp)

MARK = 'MARK-host-detail'
REFUSED_WHOLE = 'affects the whole cluster'
REFUSED_NODE = 'none of your guests run on this node'


def _pve(url, *a, **k):
    """Proxmox VE as the session and _api_get see it: every answer carries MARK."""
    tail = url.split('/api2/json/', 1)[-1]
    if tail == 'nodes':
        return _resp(200, [{'node': n, 'status': 'online'} for n in ('n1', 'n2', 'n3')])
    if tail.endswith('/network') and tail.startswith('nodes/'):
        r = _resp(200, [{'iface': 'vmbr0', 'type': 'bridge', 'comments': MARK}])
        r.json.return_value['changes'] = f'--- {MARK}'
        return r
    if tail.endswith(('firewall/options', 'cluster/options', 'config/join')):
        return _resp(200, {'enable': 1, 'tag': MARK, 'nodelist': [], 'totem': {}})
    return _resp(200, [{'id': tail, 'tag': MARK, 'iommugroup': 1}])


def _stub(mgr, monkeypatch):
    for name in ('get_node_disks', 'get_node_lvm', 'get_node_lvmthin', 'get_node_zfs',
                 'get_node_network_config', 'get_node_certificates', 'get_host_pifs', 'get_bonds',
                 'get_network_list', 'get_iso_list', 'get_node_rrddata', 'get_metric_servers'):
        getattr(mgr, name).return_value = [{'name': name, 'tag': MARK}]
    for name in ('get_node_disk_smart', 'get_node_summary', 'get_node_netstats',
                 'get_node_cluster_health', 'get_node_sensors', 'get_node_dns', 'get_node_time',
                 'get_node_subscription', 'get_cluster_fingerprint'):
        getattr(mgr, name).return_value = {'success': True, 'tag': MARK}
    mgr.get_node_hosts.return_value = f'10.9.9.2 {MARK}'
    mgr.get_cluster_hw_rollup.return_value = {'health': 'warning', 'available': True,
                                              'degraded': [{'node': 'n2', 'tag': MARK}]}
    mgr.member_node_ip.return_value = '10.7.7.1'
    mgr._create_session.return_value.get.side_effect = _pve
    mgr._api_get.side_effect = _pve
    import pegaprox.api.nodes as nodes_api
    from pegaprox.core import redfish
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (True, None))
    monkeypatch.setattr(redfish, 'read_node_hardware', lambda *a, **k: {'tag': MARK})


# refused to a confined caller on any node, the one its own guest runs on (n1) included
WHOLE_CLUSTER = [
    '/nodes/n1/disks', '/nodes/n1/disks/sda/smart', '/nodes/n1/disks/lvm',
    '/nodes/n1/disks/lvmthin', '/nodes/n1/disks/zfs',
    '/nodes/n1/network', '/nodes/n1/network/changes', '/nodes/n1/netstats',
    '/nodes/n1/pifs', '/nodes/n1/bonds', '/nodes/n1/dns', '/nodes/n1/hosts',
    '/nodes/n1/certificates', '/nodes/n1/subscription', '/nodes/n1/cluster-health',
    '/nodes/n1/sensors', '/nodes/n1/hardware', '/nodes/n1/multipath',
    '/nodes/n1/smbios-autoconfig/status',
    '/datacenter/firewall/options', '/datacenter/firewall/rules', '/datacenter/firewall/groups',
    '/datacenter/firewall/aliases', '/datacenter/firewall/ipset',
    '/datacenter/sdn', '/datacenter/sdn/zones', '/datacenter/sdn/zones/z1',
    '/datacenter/sdn/vnets', '/datacenter/sdn/vnets/v1', '/datacenter/sdn/vnets/v1/subnets',
    '/datacenter/sdn/fabrics', '/datacenter/sdn/routemaps', '/datacenter/sdn/prefixlists',
    '/datacenter/sdn/controllers', '/datacenter/sdn/ipams', '/datacenter/sdn/dns',
    '/datacenter/subscriptions', '/datacenter/metric-servers', '/datacenter/multipath/status',
    '/datacenter/cluster-info', '/datacenter/join-info',
    '/datacenter/mapping/pci', '/datacenter/mapping/usb', '/fingerprint',
    '/smbios-autoconfig/status-all', '/hardware/health',
]
# the stub hands these MARK, so the mirror can say the operator got the data itself
OPERATOR_SEES_MARK = {p for p in WHOLE_CLUSTER if 'multipath' not in p and 'smbios' not in p
                      and p not in ('/datacenter/cluster-info', '/datacenter/subscriptions')}


@pytest.mark.parametrize('path', WHOLE_CLUSTER)
def test_a_confined_caller_is_refused_host_details_and_datacenter_reads(who, mgr, monkeypatch, path):
    _stub(mgr, monkeypatch)
    for kind in CONFINED:
        mgr.reset_mock()
        r = who[kind].get(BASE + path)
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and REFUSED_WHOLE in body, (kind, path, r.status_code, body[:200])
        assert MARK not in body
        # refused before the cluster is asked
        assert not mgr._create_session.return_value.get.called and not mgr._api_get.called, (kind, path)
        asked = [c for c in mgr.method_calls if c[0] not in ('get_vm_resources',)]
        assert not asked, (kind, path, asked)
    for kind in WHOLE:
        r = who[kind].get(BASE + path)
        body = r.get_data(as_text=True)
        assert REFUSED_WHOLE not in body, (kind, path, r.status_code, body[:200])
        if path in OPERATOR_SEES_MARK:
            assert r.status_code == 200 and MARK in body, (kind, path, r.status_code, body[:200])


# what the node page and the guest dialogs (NIC, CD/ISO, PCI/USB passthrough, create,
# migrate) read: on the node of one of the caller's own guests only
NODE_OF_A_GUEST = ['/summary', '/ip', '/rrddata', '/time', '/temperature-history',
                   '/metrics-history?from={start}&to={end}', '/networks', '/isos',
                   '/hardware/pci', '/hardware/usb']


def _node_path(node, tail):
    now = int(time.time())
    return f'{BASE}/nodes/{node}' + tail.format(start=now - 3600, end=now)


@pytest.mark.parametrize('tail', NODE_OF_A_GUEST)
def test_a_confined_caller_reads_a_node_only_where_one_of_its_guests_runs(who, mgr, monkeypatch, tail):
    _stub(mgr, monkeypatch)
    for kind in CONFINED:
        r = who[kind].get(_node_path('n2', tail))
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and REFUSED_NODE in body, (kind, tail, r.status_code, body[:200])
        assert MARK not in body
        for node in sorted(THEIRS):
            r = who[kind].get(_node_path(node, tail))
            assert r.status_code == 200, (kind, tail, node, r.status_code, r.get_data(as_text=True)[:200])
    for kind in WHOLE:
        r = who[kind].get(_node_path('n2', tail))
        assert r.status_code == 200, (kind, tail, r.status_code, r.get_data(as_text=True)[:200])


def test_the_nic_dialog_of_their_guest_keeps_the_bridges_and_the_sdn_vnets(who, mgr, monkeypatch):
    _stub(mgr, monkeypatch)
    mgr.get_network_list.return_value = [
        {'iface': 'vmbr0', 'type': 'bridge', 'source': 'local'},
        {'iface': 'tenantA', 'type': 'sdn_vnet', 'source': 'sdn', 'zone': 'z1'}]
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/nodes/n1/networks')
        assert r.status_code == 200
        assert [b['iface'] for b in r.get_json()] == ['vmbr0', 'tenantA'], kind
        assert who[kind].get(f'{BASE}/nodes/n2/networks').status_code == 403, kind


# --- /networks: the guests they may see, the nodes those run on -----------------------------

def _guest(vmid, node, name, **extra):
    return dict({'vmid': vmid, 'name': name, 'node': node, 'status': 'running', 'type': 'qemu'}, **extra)


def _cluster_networks():
    return {
        'networks': [
            # first listed by n2: its address is n2's
            {'name': 'vmbr0', 'type': 'bridge', 'cidr': '10.9.9.2/24', 'address': '10.9.9.2',
             'gateway': '10.9.9.1', 'bridge_ports': 'eno1', 'comments': 'n2 uplink',
             'autostart': 1, 'active': 1, 'nodes': ['n2', 'n1', 'n3'],
             'vms': [_guest(100, 'n1', 'portal-web', iface='net0'),
                     _guest(200, 'n2', 'other-app', iface='net0')]},
            {'name': 'vmbr1', 'type': 'bridge', 'cidr': '10.5.5.1/24', 'address': '10.5.5.1',
             'gateway': '', 'bridge_ports': 'eno2', 'comments': 'n1 storage',
             'autostart': 1, 'active': 1, 'nodes': ['n1'],
             'vms': [_guest(101, 'n3', 'portal-db', iface='net1')]},
            # on n2 only, with nobody's guest of theirs
            {'name': 'vmbr9', 'type': 'bridge', 'cidr': '10.6.6.2/24', 'address': '10.6.6.2',
             'gateway': '', 'bridge_ports': 'eno9', 'comments': 'backup net',
             'autostart': 1, 'active': 1, 'nodes': ['n2'],
             'vms': [_guest(200, 'n2', 'other-app', iface='net1')]},
        ],
        'storage_assignments': [
            {'storage': 'local-lvm', 'vms': [_guest(100, 'n1', 'portal-web', slot='scsi0'),
                                             _guest(200, 'n2', 'other-app', slot='scsi0')]},
            {'storage': 'tank', 'vms': [_guest(200, 'n2', 'other-app', slot='scsi1')]},
        ],
    }


def test_networks_carry_the_guests_and_nodes_of_a_confined_caller_only(who, mgr):
    answer = _cluster_networks()
    kept = copy.deepcopy(answer)
    mgr.get_cluster_networks.return_value = answer
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/networks')
        assert r.status_code == 200, (kind, r.data)
        body = r.get_json()
        text = r.get_data(as_text=True)
        assert 'other-app' not in text and '10.9.9.2' not in text and 'eno9' not in text, kind
        nets = {n['name']: n for n in body['networks']}
        assert set(nets) == {'vmbr0', 'vmbr1'}, kind
        assert [v['vmid'] for v in nets['vmbr0']['vms']] == [100]
        assert nets['vmbr0']['nodes'] == ['n1', 'n3']
        # settings of a bridge another node listed first are not theirs
        assert nets['vmbr0']['address'] == nets['vmbr0']['gateway'] == nets['vmbr0']['comments'] == ''
        # their own node's bridge keeps its settings, as /topology shows them
        assert nets['vmbr1']['address'] == '10.5.5.1' and nets['vmbr1']['nodes'] == ['n1']
        assert [v['vmid'] for v in nets['vmbr1']['vms']] == [101]
        assert body['storage_assignments'] == [
            {'storage': 'local-lvm', 'vms': [_guest(100, 'n1', 'portal-web', slot='scsi0')]}]
    # the manager's answer is the cache every caller is served from: never written to
    assert answer == kept
    for kind in WHOLE:
        assert who[kind].get(f'{BASE}/networks').get_json() == kept, kind


@pytest.mark.parametrize('kind', CONFINED)
def test_networks_say_so_when_a_confined_callers_guests_cannot_be_read(who, mgr, kind):
    mgr.get_cluster_networks.return_value = _cluster_networks()
    mgr.get_vm_resources.return_value = UnreadList()
    r = who[kind].get(f'{BASE}/networks')
    assert r.status_code == 503 and 'other-app' not in r.get_data(as_text=True)
    # decided before the walk over every guest's config
    assert not mgr.get_cluster_networks.called
    assert who['operator'].get(f'{BASE}/networks').status_code == 200


# --- the HA manager status: the HA guests they may see --------------------------------------

def _manager_status():
    return {
        'quorum': {'node': 'n1', 'quorate': '1'},
        'manager_status': {
            'master_node': 'n1', 'timestamp': 1762500000,
            'node_status': {'n1': 'online', 'n2': 'online', 'n3': 'online'},
            'service_status': {'vm:100': {'node': 'n1', 'state': 'started'},
                               'vm:101': {'node': 'n3', 'state': 'started'},
                               'vm:200': {'node': 'n2', 'state': 'started'}},
            'relocate_trial': {'vm:200': 1},
        },
        'lrm_status': {
            'n1': {'mode': 'active', 'state': 'active',
                   'results': {'u1': {'sid': 'vm:100', 'exit_code': 0}}},
            'n2': {'mode': 'active', 'state': 'active',
                   'results': {'u2': {'sid': 'vm:200', 'exit_code': 0}}},
            'n3': {'mode': 'active', 'state': 'active',
                   'results': {'u3': {'sid': 'vm:101', 'exit_code': 0},
                               'u4': {'sid': 'vm:200', 'exit_code': 0}}},
        },
    }


def _current_status():
    return [{'id': 'quorum', 'type': 'quorum', 'node': 'n1', 'quorate': 1},
            {'id': 'master', 'type': 'master', 'node': 'n1'},
            {'id': 'lrm:n1', 'type': 'lrm', 'node': 'n1'},
            {'id': 'lrm:n2', 'type': 'lrm', 'node': 'n2'},
            {'id': 'service:vm:100', 'type': 'service', 'sid': 'vm:100', 'node': 'n1'},
            {'id': 'service:vm:200', 'type': 'service', 'sid': 'vm:200', 'node': 'n2'}]


def _ha_answers(mgr, manager_status):
    def get(url, *a, **k):
        if url.endswith('ha/status/manager_status'):
            return _resp(200, manager_status) if manager_status is not None else _resp(500, None)
        if url.endswith('ha/status/current'):
            return _resp(200, _current_status())
        return _resp(404, None)
    mgr._create_session.return_value.get.side_effect = get


def test_the_ha_status_carries_the_ha_guests_of_a_confined_caller_only(who, mgr):
    _ha_answers(mgr, _manager_status())
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/datacenter/ha/status')
        assert r.status_code == 200, (kind, r.data)
        body = r.get_json()
        assert 'vm:200' not in r.get_data(as_text=True), kind
        ms = body['manager_status']
        assert set(ms['service_status']) == {'vm:100', 'vm:101'}
        assert set(ms['node_status']) == THEIRS and ms['master_node'] == 'n1'
        assert set(body['lrm_status']) == THEIRS
        assert [r['sid'] for r in body['lrm_status']['n3']['results'].values()] == ['vm:101']
        assert body['quorum'] == {'node': 'n1', 'quorate': '1'}
    for kind in WHOLE:
        assert who[kind].get(f'{BASE}/datacenter/ha/status').get_json() == _manager_status(), kind


def test_the_older_ha_status_list_is_cut_the_same_way(who, mgr):
    _ha_answers(mgr, None)
    for kind in CONFINED:
        rows = who[kind].get(f'{BASE}/datacenter/ha/status').get_json()
        assert [r['id'] for r in rows] == ['quorum', 'master', 'lrm:n1', 'service:vm:100'], kind
    for kind in WHOLE:
        assert who[kind].get(f'{BASE}/datacenter/ha/status').get_json() == _current_status(), kind


@pytest.mark.parametrize('kind', CONFINED)
def test_the_ha_status_says_so_when_a_confined_callers_guests_cannot_be_read(who, mgr, kind):
    _ha_answers(mgr, _manager_status())
    mgr.get_vm_resources.return_value = UnreadList()
    r = who[kind].get(f'{BASE}/datacenter/ha/status')
    assert r.status_code == 503 and 'vm:200' not in r.get_data(as_text=True)
    assert who['operator'].get(f'{BASE}/datacenter/ha/status').status_code == 200


# --- no read of a node detail or of the datacenter goes without a scope gate ----------------

SCOPE_GATES = ('require_unconfined', 'require_guest_node', 'caller_guest_nodes', 'scope_vm_rows',
               'user_can_access_vm', 'caller_is_scoped', 'sees_whole_maintenance',
               '_dir_mapping_manager', '_ha_sid_authorized', '_job_for_caller', 'ha_status_answer')
# reads that answer every caller with cluster access alike, and why
OPEN_ON_PURPOSE = {
    # counts and totals of the whole cluster, no node and no guest named
    'vms.get_datacenter_status',
    # the next free VMID of the cluster (the node is not asked), which a create dialog reads
    'vms.get_next_vmid_for_node_api',
    # the SMBIOS strings PegaProx writes into new guests, no data of a host
    'nodes.get_smbios_autoconfig',
}


def test_every_node_detail_and_datacenter_read_has_a_scope_gate(api):
    assert OPEN_ON_PURPOSE <= set(api.app.view_functions), OPEN_ON_PURPOSE - set(api.app.view_functions)
    missing = []
    for rule in api.app.url_map.iter_rules():
        if 'GET' not in rule.methods:
            continue
        path = rule.rule
        if not path.startswith('/api/clusters/<cluster_id>/'):
            continue
        if '/vms/' in path or '/datastores/' in path:
            continue        # per-guest routes and storages, gated per object elsewhere
        # every read of the nodes and datacenter blueprints, and a read about one node or the
        # datacenter whichever blueprint registers it (groups, settings, ceph, storage, reports)
        if rule.endpoint.split('.')[0] not in ('nodes', 'datacenter') \
                and '<node' not in path and '/datacenter/' not in path:
            continue
        if rule.endpoint in OPEN_ON_PURPOSE:
            continue
        src = inspect.getsource(inspect.unwrap(api.app.view_functions[rule.endpoint]))
        if not any(g in src for g in SCOPE_GATES):
            missing.append(f'{path} ({rule.endpoint})')
    assert not missing, '\n'.join(sorted(missing))
