# -*- coding: utf-8 -*-
"""
Network Topology — MK May 2026.

Aggregates Proxmox cluster network topology into a single graph payload the
UI can render with plain SVG (no D3 / cytoscape dep). The frontend draws a
hierarchical layout:

    cluster
       │
    ┌──┴──┬──────┬──────┐
   node1 node2  node3  ...
    │
   ┌┴────┬──────┬──────┐
  bond0 vmbr0 vmbr1   ...      (NICs / bridges / bonds)
    │
   VM1  VM2  VM3                (qemu/lxc connected to that bridge)

Returns:
    {
      'cluster': {id, name},
      'nodes': [{id, kind, label, parent_id?, meta?}, ...],
      'links': [{source, target, kind?}, ...],
    }

`kind`: cluster | node | bridge | bond | sdn_vnet | vm | ct
"""
import logging
from flask import Blueprint, jsonify

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access

bp = Blueprint('topology', __name__)


def _net_state_for_node(mgr, node):
    """Return the per-node network list (bridges, bonds, eth, etc.)."""
    try:
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/network"
        r = mgr._api_get(url)
        if r and r.status_code == 200:
            return r.json().get('data') or []
    except Exception as e:
        logging.debug(f"[topology] {node} network fetch failed: {e}")
    return []


def _vm_net_bridges(vm_cfg):
    """Extract bridge names from a VM/CT config dict (net0..netN keys)."""
    bridges = []
    for k, v in (vm_cfg or {}).items():
        if not k.startswith('net'): continue
        try:
            for part in str(v).split(','):
                part = part.strip()
                if part.startswith('bridge='):
                    bridges.append(part.split('=', 1)[1])
        except Exception:
            continue
    return bridges


@bp.route('/api/clusters/<cluster_id>/topology', methods=['GET'])
@require_auth(perms=['cluster.view'])
def topology(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    mgr = cluster_managers[cluster_id]

    nodes_out = []
    links_out = []

    cluster_label = getattr(getattr(mgr, 'config', None), 'name', cluster_id) or cluster_id
    nodes_out.append({'id': f'cluster:{cluster_id}', 'kind': 'cluster',
                      'label': cluster_label})

    # ── PVE Nodes
    try:
        pve_nodes = list((mgr.nodes or {}).keys())
    except Exception:
        pve_nodes = []

    # ── per-node bridges/bonds
    bridges_by_node = {}  # node -> list of {iface, type, ports?, vlan_aware?, address?}
    for node in pve_nodes:
        node_id = f'node:{node}'
        node_meta = {}
        try:
            ndata = (mgr.nodes or {}).get(node) or {}
            node_meta = {
                'cpu_pct': round((ndata.get('cpu', 0) or 0) * 100, 1),
                'maxcpu': ndata.get('maxcpu', 0),
                'mem_pct': round((ndata.get('mem', 0) or 0) / max(ndata.get('maxmem', 1), 1) * 100, 1),
                'status': ndata.get('status', 'unknown'),
            }
        except Exception:
            pass
        nodes_out.append({'id': node_id, 'kind': 'node', 'label': node,
                          'parent_id': f'cluster:{cluster_id}', 'meta': node_meta})
        links_out.append({'source': f'cluster:{cluster_id}', 'target': node_id, 'kind': 'tree'})

        bridges = []
        for nic in _net_state_for_node(mgr, node):
            t = nic.get('type', '')
            iface = nic.get('iface', '')
            if not iface: continue
            if t in ('bridge', 'bond', 'OVSBridge', 'OVSBond'):
                bridges.append({
                    'iface': iface,
                    'type': t,
                    'ports': (nic.get('bridge_ports') or nic.get('slaves') or '').split() if nic.get('bridge_ports') or nic.get('slaves') else [],
                    'address': nic.get('address') or nic.get('cidr') or '',
                    'vlan_aware': bool(nic.get('bridge_vlan_aware')),
                })
                br_id = f'br:{node}:{iface}'
                nodes_out.append({'id': br_id, 'kind': 'bridge' if t.endswith('Bridge') or t == 'bridge' else 'bond',
                                  'label': iface, 'parent_id': node_id, 'meta': {
                                      'address': nic.get('address') or nic.get('cidr') or '',
                                      'type': t, 'vlan_aware': bool(nic.get('bridge_vlan_aware')),
                                      'ports': (nic.get('bridge_ports') or nic.get('slaves') or ''),
                                  }})
                links_out.append({'source': node_id, 'target': br_id, 'kind': 'has-iface'})
        bridges_by_node[node] = bridges

    # ── SDN VNets (cluster-wide, may attach to any node's vmbr)
    try:
        url = f"https://{mgr.host}:8006/api2/json/cluster/sdn/vnets"
        r = mgr._api_get(url)
        if r and r.status_code == 200:
            for v in (r.json().get('data') or []):
                vnet = v.get('vnet') or v.get('name')
                if not vnet: continue
                vid = f'sdn:{vnet}'
                nodes_out.append({'id': vid, 'kind': 'sdn_vnet', 'label': vnet,
                                  'parent_id': f'cluster:{cluster_id}', 'meta': {
                                      'zone': v.get('zone', ''),
                                      'tag': v.get('tag'),
                                      'alias': v.get('alias'),
                                  }})
                links_out.append({'source': f'cluster:{cluster_id}', 'target': vid, 'kind': 'sdn'})
    except Exception as e:
        logging.debug(f"[topology] sdn fetch failed: {e}")

    # ── VMs / CTs grouped under their bridge
    try:
        resources = mgr.get_vm_resources() or []
    except Exception:
        resources = []
    for r in resources:
        if r.get('type') not in ('qemu', 'lxc'): continue
        node = r.get('node')
        vmid = r.get('vmid')
        if not node or vmid is None: continue
        vm_kind = 'vm' if r.get('type') == 'qemu' else 'ct'
        vm_id = f"{vm_kind}:{vmid}"
        nodes_out.append({'id': vm_id, 'kind': vm_kind,
                          'label': r.get('name') or str(vmid),
                          'parent_id': f'node:{node}',
                          'meta': {
                              'vmid': vmid,
                              'status': r.get('status'),
                              'tags': r.get('tags') or '',
                          }})

        # fetch VM config to get net0/net1/...
        try:
            cfg_url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{r['type']}/{vmid}/config"
            cfg_resp = mgr._api_get(cfg_url)
            cfg = cfg_resp.json().get('data') if cfg_resp and cfg_resp.status_code == 200 else {}
        except Exception:
            cfg = {}
        for br_name in _vm_net_bridges(cfg):
            # Try matching to a same-node bridge first; fall back to any node's
            br_target = f'br:{node}:{br_name}'
            if not any(n['id'] == br_target for n in nodes_out):
                # might be an SDN vnet
                sdn_target = f'sdn:{br_name}'
                if any(n['id'] == sdn_target for n in nodes_out):
                    br_target = sdn_target
                else:
                    # bridge wasn't seen — skip (could be on another node we didn't fully scan)
                    continue
            links_out.append({'source': vm_id, 'target': br_target, 'kind': 'attached'})

    return jsonify({
        'cluster': {'id': cluster_id, 'name': cluster_label},
        'nodes': nodes_out,
        'links': links_out,
        'counts': {
            'nodes': len(pve_nodes),
            'bridges': sum(len(b) for b in bridges_by_node.values()),
            'vms': len([r for r in resources if r.get('type') == 'qemu']),
            'cts': len([r for r in resources if r.get('type') == 'lxc']),
        },
    })
