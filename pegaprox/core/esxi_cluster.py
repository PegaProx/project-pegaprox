# -*- coding: utf-8 -*-
"""
ESXi Cluster Manager Facade - Layer 5
Wraps VMwareManager to look like a cluster manager for XHM integration.
NS: Mar 2026 - so the migration engine treats ESXi like PVE/XCP-ng
"""

import logging
import time

logger = logging.getLogger(__name__)


class _ESXiConfig:
    """duck-type config object for SSH access to ESXi host"""
    def __init__(self, vmw):
        self.host = vmw.host
        self.user = vmw.username
        self.pass_ = vmw.password
        self.ssh_user = 'root'  # ESXi SSH is always root
        self.ssh_key = ''
        self.ssh_port = 22
        self.ssl_verification = not vmw.ssl_verify  # invert


class ESXiClusterManager:
    """Makes an ESXi host look like a PegaProx cluster for XHM.
    Delegates everything to the underlying VMwareManager."""

    cluster_type = 'esxi'

    def __init__(self, cluster_id, vmware_mgr):
        self.id = cluster_id
        self._vmware = vmware_mgr
        self.host = vmware_mgr.host
        self.config = _ESXiConfig(vmware_mgr)
        self.logger = logging.getLogger(f'ESXi:{cluster_id[:8]}')

        # HA stubs (not applicable for ESXi in XHM)
        self.ha_enabled = False
        self.ha_node_status = {}
        self.nodes_in_maintenance = set()

    @property
    def is_connected(self):
        return self._vmware.connected

    @property
    def name(self):
        return self._vmware.name

    def connect(self):
        return self._vmware.connect()

    # -- VM operations (read-only for migration planning) --

    def get_vms(self):
        """list VMs in a format close to what PVE/XCP returns"""
        result = self._vmware.get_vms()
        if 'error' in result:
            return []
        raw = result.get('data', [])
        vms = []
        for v in raw:
            power = v.get('power_state', 'POWERED_OFF')
            status = 'running' if power == 'POWERED_ON' else 'stopped'
            vms.append({
                'vmid': v.get('vm', v.get('id', '')),
                'name': v.get('name', ''),
                'status': status,
                'type': 'qemu',
                'node': self.host,
                'maxmem': v.get('memory_size_MiB', 0) * 1024 * 1024,
                'maxcpu': v.get('cpu_count', 1),
                '_esxi_id': v.get('vm', v.get('id', '')),
            })
        return vms

    def get_vm_config(self, vmid):
        """get detailed VM config for migration planning"""
        return self._vmware.get_vm_disks_for_export(str(vmid))

    def get_nodes(self):
        return [{
            'node': self.host,
            'status': 'online',
            'type': 'node',
            'id': self.id,
        }]

    def get_storages(self, node=None):
        result = self._vmware.get_datastores()
        if 'error' in result:
            return []
        stores = []
        for ds in result.get('data', []):
            stores.append({
                'storage': ds.get('name', ds.get('datastore', '')),
                'type': 'vmfs',
                'total': ds.get('capacity', 0),
                'used': ds.get('capacity', 0) - ds.get('free_space', 0),
                'avail': ds.get('free_space', 0),
            })
        return stores

    def get_networks(self, node=None):
        result = self._vmware.get_networks()
        if 'error' in result:
            return []
        nets = []
        for n in result.get('data', []):
            nets.append({
                'iface': n.get('name', n.get('network', '')),
                'type': 'bridge',
            })
        return nets

    def get_node_status(self):
        """minimal metrics for sidebar display"""
        return {
            self.host: {
                'status': 'online' if self.is_connected else 'offline',
                'cpu_percent': 0,
                'mem_used': 0,
                'mem_total': 0,
                'mem_percent': 0,
                'uptime': 0,
                'maintenance_mode': False,
                'offline': not self.is_connected,
                'pveversion': f"ESXi {self._vmware.api_version or ''}".strip(),
            }
        }

    def get_vm_resources(self, max_age: float = 0.0):
        """for SSE broadcast compatibility.
        #781 — accept+ignore max_age so Proxmox-shaped callers (/resources, topology) don't
        TypeError on an ESXi cluster; there's no cached snapshot here, so it's always fresh."""
        return self.get_vms() + self.get_nodes()

    # migration helpers

    def get_vm_disks_for_export(self, vmid):
        return self._vmware.get_vm_disks_for_export(str(vmid))

    def create_migration_snapshot(self, vmid):
        return self._vmware.create_migration_snapshot(str(vmid))

    def delete_migration_snapshot(self, vmid):
        return self._vmware.delete_migration_snapshot(str(vmid))
