# -*- coding: utf-8 -*-
"""
PegaProx Task Models - Layer 0
No pegaprox imports allowed.
"""

from datetime import datetime


# MK Oct 2026 - how long a guest the balancer moved is left where it is (was 900 s,
# fixed). Per cluster; the API refuses anything outside the range.
BALANCER_COOLDOWN_DEFAULT = 900
BALANCER_COOLDOWN_MIN = 60
BALANCER_COOLDOWN_MAX = 86400


def balancer_cooldown(value):
    """A stored or sent cooldown as whole seconds inside the range, the default when it
    is no number at all."""
    if isinstance(value, bool):
        return BALANCER_COOLDOWN_DEFAULT
    try:
        secs = int(value)
    except (TypeError, ValueError):
        return BALANCER_COOLDOWN_DEFAULT
    return min(max(secs, BALANCER_COOLDOWN_MIN), BALANCER_COOLDOWN_MAX)


def endpoint_port(value):
    """A port as a plain int inside 1..65535, or None when it is unset or unusable."""
    # bool is an int in Python and True would become port 1. A fractional number is not
    # a port either, and int() would quietly make 2201.5 into 2201.
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port != value and str(value).strip() != str(port):
        return None
    return port if 1 <= port <= 65535 else None


def endpoint_host(value):
    """An address as a bare host, or None.

    Only the shape is judged here, not whether it resolves. A scheme, a path or a
    port glued to the address are all rejected rather than cleaned up: an endpoint
    is dialled by several call paths that each build their own URL, and one of them
    would end up with "https://host:2201:8006".
    """
    if not isinstance(value, str):
        return None
    host = value.strip().strip("[]")
    if not host or len(host) > 255:
        return None
    if any(c in host for c in " \t/\\@?#"):
        return None
    # "host:2201" is a host and a port, and the port has its own field. One colon is
    # that; an IPv6 address has at least two and keeps them.
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        return None
    return host


def normalize_node_endpoints(raw):
    """{node: {host, ssh_port, api_port}} with everything unusable dropped.

    An entry that overrides nothing is dropped too, so the stored map only ever holds
    nodes that actually deviate. Never raises: a malformed map costs the override, not
    the cluster.
    """
    if not isinstance(raw, dict):
        return {}
    endpoints = {}
    for node, spec in raw.items():
        if not isinstance(node, str) or not node.strip():
            continue
        if not isinstance(spec, dict):
            continue
        entry = {}
        host = endpoint_host(spec.get("host"))
        if host:
            entry["host"] = host
        for key in ("ssh_port", "api_port"):
            port = endpoint_port(spec.get(key))
            if port is not None:
                entry[key] = port
        if entry:
            endpoints[node.strip()] = entry
    return endpoints


def node_endpoint_of(config, node_name) -> dict:
    """What a cluster overrides for one node: {host?, ssh_port?, api_port?}.

    Empty for every node of an ordinary cluster, which is all of them until an operator
    fills the map in, so the lookup stays off the hot paths by being a dict miss rather
    than a probe.
    """
    if not node_name:
        return {}
    endpoints = getattr(config, 'node_endpoints', None) or {}
    entry = endpoints.get(node_name)
    if entry is None and endpoints and isinstance(node_name, str):
        # the console context also lists a node under its lowercase alias, and an alias
        # must get the node's own entry, not the cluster's ports
        low = node_name.lower()
        entry = next((e for n, e in endpoints.items() if isinstance(n, str) and n.lower() == low), None)
    return entry if isinstance(entry, dict) else {}


def ssh_port_of(config, node_name=None) -> int:
    """The SSH port to dial one node at, its own or the cluster's."""
    port = node_endpoint_of(config, node_name).get('ssh_port')
    if port:
        return int(port)
    return getattr(config, 'ssh_port', 22) or 22


def api_port_of(config, node_name=None) -> int:
    """The API port to dial one node at, its own or the cluster's."""
    port = node_endpoint_of(config, node_name).get('api_port')
    if port:
        return int(port)
    return getattr(config, 'api_port', 8006) or 8006


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
        self.note = None  # NS jul 2026 - informational note (e.g. single-node: no evacuation target)
        # MK Oct 2026 (#763) - templates move only when asked; the ones that stay say why
        self.migrate_templates = False
        self.templates_moved = []
        self.templates_left = []
        # #954 - negative affinity rules this maintenance holds off, and the ones Proxmox kept on
        self.relax_anti_affinity = False
        self.ha_rules_off = []
        self.ha_rules_kept_on = []
        # Sep 2026 - guests this drain had to place off their plb_pin_ node because
        # no pinned node could take them. Reported, not an error: the drain is what
        # the operator asked for, and pin reconciliation returns them afterwards.
        self.off_pin_vms = []

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
            'native_ha': self.native_ha,
            'note': self.note,
            'templates_moved': self.templates_moved,
            'templates_left': self.templates_left,
            'ha_rules_off': self.ha_rules_off,
            'ha_rules_kept_on': self.ha_rules_kept_on,
            'off_pin_vms': self.off_pin_vms,
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
        self.reboot_issued = False
        self.back_online = False
        self.reboot_waited = 0

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
        self.pass_ = cluster_data.get('pass', '')
        self.ssl_verification = cluster_data.get('ssl_verification', False)
        self.migration_threshold = cluster_data.get('migration_threshold', 20)
        self.migration_tolerance = cluster_data.get('migration_tolerance', 10)
        self.migration_cooldown = balancer_cooldown(
            cluster_data.get('migration_cooldown', BALANCER_COOLDOWN_DEFAULT))
        self.check_interval = cluster_data.get('check_interval', 300)
        self.auto_migrate = cluster_data.get('auto_migrate', False)
        self.balance_containers = cluster_data.get('balance_containers', False)
        self.balance_local_disks = cluster_data.get('balance_local_disks', False)
        # MK Jul 2026 (#426) — opt-in: derive affinity/anti-affinity/ignore/pin
        # placement rules from ProxLB-convention VM tags. Off = zero change.
        self.proxlb_tags_enabled = cluster_data.get('proxlb_tags_enabled', False)
        # Pin reconciliation migrates a guest back onto its plb_pin_ node only
        # when this is on; otherwise off-pin guests are only reported.
        self.proxlb_pins_auto_migrate = cluster_data.get('proxlb_pins_auto_migrate', False)
        # A plb_pin_ tag ranks evacuation targets but does not veto a drain - a
        # guest stranded on a node about to reboot is worse than a guest in the
        # wrong place. Turn this on where a pin is a hard constraint (licensing,
        # PCI passthrough, local disks) and the drain should fail instead.
        self.proxlb_pins_strict = cluster_data.get('proxlb_pins_strict', False)
        self.dry_run = cluster_data.get('dry_run', False)
        self.enabled = cluster_data.get('enabled', True)
        self.ha_enabled = cluster_data.get('ha_enabled', False)
        self.fallback_hosts = cluster_data.get('fallback_hosts', [])
        self.ssh_user = cluster_data.get('ssh_user', '')
        self.ssh_key = cluster_data.get('ssh_key', '')
        self.ssh_port = cluster_data.get('ssh_port', 22)
        # MK Sep 2026 (#941) — hard off switch. Everything that reaches a node over SSH
        # goes through PegaProxManager._ssh_connect, so this turns the lot off for this
        # cluster: node shell, VNC tunnel, the LVM snapshot probe, the hardening checks.
        # MK Nov 2026 - the node shell does not (its login is the operator's), it asks
        # api/helpers.node_shell_refusal
        self.ssh_disabled = bool(cluster_data.get('ssh_disabled', False))
        # MK May 2026 — Proxmox API port. Default :8006 covers ~all installs,
        # but ops running PVE on a non-standard port (firewall constraint,
        # multi-tenant single-IP, hardened jumpbox) need to override this.
        # NOTE: We do NOT support reverse-proxied PVE — direct TLS to PVE is
        # the only supported path, by design (no MitM-able intermediate hop).
        try:
            self.api_port = int(cluster_data.get('api_port', 8006) or 8006)
            if not (1 <= self.api_port <= 65535):
                self.api_port = 8006
        except (TypeError, ValueError):
            self.api_port = 8006
        # A node is normally reached at the address it reports for itself and at the
        # cluster's ssh_port/api_port. Where that is not true -- a NAT forward per node
        # in front of one public address, a node behind its own firewall -- the node
        # gets an entry here and that entry wins over discovery for it.
        self.node_endpoints = normalize_node_endpoints(cluster_data.get('node_endpoints', {}))
        self.ha_settings = cluster_data.get('ha_settings', {})
        self.excluded_nodes = cluster_data.get('excluded_nodes', [])
        self.smbios_autoconfig = cluster_data.get('smbios_autoconfig', {})
        self.api_token_user = cluster_data.get('api_token_user', '')    # NS Mar 2026 - e.g. "root@pam!pegaprox"
        self.api_token_secret = cluster_data.get('api_token_secret', '')
        # MK Apr 2026 — VNC SSH-Tunnel-Mode. When True, the VNC websocket from
        # PegaProx to PVE is routed through the cluster's existing SSH connection
        # (same creds as ssh_user/ssh_key/pass_) instead of going direct to
        # https://pve:8006. Defeats TLS-inspection middleboxes that re-encrypt
        # the second leg and modify binary RFB bytes. Customer-side opt-in.
        self.vnc_tunnel = cluster_data.get('vnc_tunnel', False)
        # MK May 2026 — worldmap location. Both None until the operator sets it
        # via the Cluster Edit dialog. location_label is a free-text hint
        # ("Frankfurt DC1") shown in tooltips next to the dot.
        self.latitude = cluster_data.get('latitude')
        self.longitude = cluster_data.get('longitude')
        self.location_label = cluster_data.get('location_label', '') or ''
        # MK Aug 2026 (#689) — optional FQDN suffix for the node Web-UI links. Short node names
        # (pve01) get "<suffix>" appended → pve01.example.local:8006. Empty string = links use the
        # node IP/host as before.
        self.node_ui_suffix = (cluster_data.get('node_ui_suffix', '') or '').strip().lstrip('.')
        # MK Oct 2026 - CIDR the remote migrations into this cluster dial its nodes in
        # (core/transfer_net.py). Empty = the management host, as before.
        self.transfer_network = str(cluster_data.get('transfer_network', '') or '').strip()
        # NS May 2026 (#364) — load-balancer settings finally hydrated from db.
        # Were API-settable but never persisted before, so users saw "saved"
        # toasts that reverted within seconds.
        self.predictive_balancing = cluster_data.get('predictive_balancing', False)
        self.predictive_threshold = cluster_data.get('predictive_threshold', 0.0)
        self.balance_cpu_weight = cluster_data.get('balance_cpu_weight', 1.0)
        self.balance_mem_weight = cluster_data.get('balance_mem_weight', 1.0)
        self.balance_io_weight = cluster_data.get('balance_io_weight', 1.0)
        self.cpu_baseline = cluster_data.get('cpu_baseline', '')
        # MK May 2026 — backup SLA tracking. Hours since last backup beyond which
        # a VM is flagged as breached. 0 = SLA tracking disabled. Warning band is
        # 80% of the limit (hardcoded for now, could be its own setting later).
        self.backup_sla_max_age_hours = int(cluster_data.get('backup_sla_max_age_hours', 0) or 0)
