# -*- coding: utf-8 -*-
"""
PegaProx Task Models - Layer 0
No pegaprox imports allowed.
"""

from datetime import datetime


class MaintenanceTask:
    """Tracks a node evacuation/maintenance task"""

    def __init__(self, node: str):
        self.node = node
        self.started_at = datetime.now()
        self.total_vms = 0
        self.migrated_vms = 0
        self.failed_vms = []
        self.pending_vms = []
        self.status = 'starting'
        self.current_vm = None
        self.error = None
        self.acknowledged = False
        self.native_ha = False  # NS feb 2026 - tracks if Proxmox native HA maintenance was used

    def to_dict(self):
        return {
            'node': self.node,
            'started_at': self.started_at.isoformat(),
            'total_vms': self.total_vms,
            'migrated_vms': self.migrated_vms,
            'failed_vms': self.failed_vms,
            'pending_vms': [{'vmid': vm.get('vmid'), 'name': vm.get('name', 'unnamed')} for vm in self.pending_vms],
            'status': self.status,
            'current_vm': self.current_vm,
            'progress_percent': round((self.migrated_vms / self.total_vms * 100) if self.total_vms > 0 else 0, 1),
            'error': self.error,
            'acknowledged': self.acknowledged,
            'native_ha': self.native_ha
        }


class UpdateTask:
    """Tracks node update progress"""

    def __init__(self, node: str, reboot: bool = True):
        self.node = node
        self.reboot = reboot
        self.started_at = datetime.now()
        self.status = 'starting'
        self.phase = 'init'
        self.output_lines = []
        self.error = None
        self.packages_upgraded = 0
        self.completed_at = None

    def add_output(self, line: str):
        self.output_lines.append({
            'timestamp': datetime.now().isoformat(),
            'text': line
        })
        # Keep only last 100 lines
        if len(self.output_lines) > 100:
            self.output_lines = self.output_lines[-100:]

    def to_dict(self):
        return {
            'node': self.node,
            'reboot': self.reboot,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'phase': self.phase,
            'output_lines': self.output_lines[-20:],  # Last 20 lines for UI
            'error': self.error,
            'packages_upgraded': self.packages_upgraded,
            'duration_seconds': (datetime.now() - self.started_at).total_seconds()
        }


class PegaProxConfig:
    """Configuration for a single Proxmox cluster"""

    def __init__(self, cluster_data):
        self.name = cluster_data['name']
        self.host = cluster_data['host']
        self.user = cluster_data['user']
        self.pass_ = cluster_data['pass']
        self.ssl_verification = cluster_data.get('ssl_verification', False)
        self.migration_threshold = cluster_data.get('migration_threshold', 20)
        self.check_interval = cluster_data.get('check_interval', 300)
        self.auto_migrate = cluster_data.get('auto_migrate', True)
        self.balance_containers = cluster_data.get('balance_containers', False)
        self.balance_local_disks = cluster_data.get('balance_local_disks', False)
        self.dry_run = cluster_data.get('dry_run', False)
        self.enabled = cluster_data.get('enabled', True)
        self.ha_enabled = cluster_data.get('ha_enabled', False)
        self.fallback_hosts = cluster_data.get('fallback_hosts', [])
        self.ssh_user = cluster_data.get('ssh_user', '')
        self.ssh_key = cluster_data.get('ssh_key', '')
        self.ssh_port = cluster_data.get('ssh_port', 22)
        self.ha_settings = cluster_data.get('ha_settings', {})
        self.excluded_nodes = cluster_data.get('excluded_nodes', [])
