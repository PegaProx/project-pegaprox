# -*- coding: utf-8 -*-
"""
XCP-ng / Xen Orchestra Pool Manager - Layer 5
XAPI (XML-RPC) connection, VM lifecycle, storage, network ops.

NS: Mar 2026 - first-class XCP-ng integration, same sidebar as Proxmox.
"""

import logging
import os
import threading
import time
import uuid as _uuid
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse, urlencode

from pegaprox.constants import LOG_DIR
from pegaprox import globals as _g
from pegaprox.core.db import get_db
from pegaprox.utils.realtime import broadcast_sse

# XenAPI is optional - only needed for XCP-ng clusters
try:
    import XenAPI
    XENAPI_AVAILABLE = True
except ImportError:
    XenAPI = None
    XENAPI_AVAILABLE = False

# state mapping: XAPI power_state -> our standard states
_POWER_STATE_MAP = {
    'Running': 'running',
    'Halted': 'stopped',
    'Suspended': 'suspended',
    'Paused': 'paused',
}


def _sanitize_str(val):
    """Strip NUL bytes and limit length. Same idea as manager.py sanitizer."""
    if not isinstance(val, str):
        return str(val) if val is not None else ''
    return val.replace('\x00', '')[:4096]


# MK May 2026 (CodeAnt #502) — defensive URL builders for the two raw-f-string
# XAPI endpoints (import_raw_vdi, rrd_updates). host_url is server-derived from
# the cluster config so direct SSRF is a stretch, but pre-validating session_id /
# vdi_uuid / path keeps the surface clean if a future caller starts passing
# externally-influenced values.
def _build_xapi_import_vdi_url(base_url: str, session_id: str, vdi_uuid: str, format_type: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("invalid scheme")
    if not parsed.hostname:
        raise ValueError("missing hostname")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", vdi_uuid or ""):
        raise ValueError("vdi_uuid must be alphanumeric / dash / underscore")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", format_type or ""):
        raise ValueError("format must be alphanumeric / dash / underscore")
    parsed = parsed._replace(path="/import_raw_vdi",
                             query=urlencode({"session_id": session_id, "vdi": vdi_uuid, "format": format_type}))
    return urlunparse(parsed)


def _build_xapi_rrd_url(base_url: str, path: str) -> str:
    if "/../" in base_url or re.search(r"/%2e%2e/", base_url, re.IGNORECASE):
        raise ValueError("path-traversal in base url")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("invalid scheme")
    if not parsed.hostname:
        raise ValueError("missing hostname")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", path or ""):
        raise ValueError("rrd path must be alphanumeric / dash / underscore")
    return urlunparse(parsed._replace(path=f"/{path}"))


class XcpngManager:
    """
    XCP-ng pool manager - duck-typed to match PegaProxManager's public interface.

    MK: intentionally no ABC - PegaProxManager is ~10k lines and retrofitting
    a base class would be a nightmare. Both types live in cluster_managers dict,
    API layer dispatches transparently.

    Not all methods are implemented yet, unfinished ones raise NotImplementedError
    so we get a clear signal instead of silent failures.
    """

    # match PegaProxManager's lock descriptions
    LOCK_DESCRIPTIONS = {
        'migrate': 'Migration in progress',
        'snapshot': 'Snapshot operation in progress',
        'clone': 'Clone operation in progress',
        'create': 'VM creation in progress',
        'suspended': 'VM suspended',
    }

    # NS: built-in template mapping for VM creation from scratch
    # keys match the os_type dropdown in the frontend
    _OS_TEMPLATE_MAP = {
        'linux': 'Other install media',
        'windows': 'Windows 10 (64-bit)',
        'windows11': 'Windows 11 (64-bit)',
        'ubuntu': 'Ubuntu Focal Fossa 20.04',
        'debian': 'Debian Bullseye 11',
        'centos': 'CentOS 8',
        'rhel': 'Red Hat Enterprise Linux 8',
        'sles': 'SUSE Linux Enterprise Server 15',
        'other': 'Other install media',
    }

    def __init__(self, cluster_id: str, config):
        self.id = cluster_id
        self.config = config
        self.cluster_type = 'xcpng'
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()
        self.last_run = None

        # XAPI session
        self._session = None
        self._session_lock = threading.Lock()
        self._last_keepalive = 0

        # connection state (same attrs as PegaProxManager)
        self.is_connected = False
        self.current_host = None
        self.connection_error = None
        self._consecutive_failures = 0
        self._last_reconnect_attempt = 0

        # node/vm caches
        self._cached_nodes = None
        self._nodes_cache_time = 0
        self._nodes_cache_ttl = 8  # seconds, same as PegaProxManager
        self._cached_vms = None
        self._vms_cache_time = 0

        # maintenance stubs (needed for API compat)
        self.nodes_in_maintenance = {}
        self.maintenance_lock = threading.Lock()
        self.nodes_updating = {}
        self.update_lock = threading.Lock()
        self.ha_enabled = False
        self.ha_node_status = {}
        self.ha_lock = threading.Lock()
        self.ha_recovery_in_progress = {}
        self._cached_node_dict = {}
        self.last_migration_log = []

        # task tracking - xapi opaque refs -> our task dicts
        self._active_tasks = {}
        self._task_lock = threading.Lock()

        # load balancing - MK Mar 2026
        from collections import defaultdict
        self._node_metrics_history = defaultdict(list)
        self._last_balance_check = 0

        # logging - per cluster, same as PegaProxManager
        self.logger = logging.getLogger(f"XCPng_{config.name}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        if self.logger.handlers:
            self.logger.handlers.clear()
        # 3h cap on the per-cluster log to keep disk under control (#345/#348).
        # MK May 2026 (#357): file handler is opt-out; level configurable.
        from pegaprox.constants import FILE_LOG_LEVEL as _FH_LVL, FILE_LOG_DISABLED as _FH_OFF
        fmt = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s')
        if not _FH_OFF:
            from pegaprox.utils.log_handler import CappedTimedFileHandler
            fh = CappedTimedFileHandler(f"{LOG_DIR}/{cluster_id}.log", when='H', interval=3, backupCount=0)
            fh.setLevel(_FH_LVL)
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)
        # MK May 2026 (#357 follow-up) — honour PEGAPROX_LOG_LEVEL on the
        # per-cluster stream handler too; the logger has propagate=False so the
        # root level alone isn't enough.
        from pegaprox.constants import LOG_LEVEL as _ENV_LOG_LEVEL
        ch = logging.StreamHandler()
        _stream_level = logging.INFO
        if _ENV_LOG_LEVEL is not None and _ENV_LOG_LEVEL > _stream_level:
            _stream_level = _ENV_LOG_LEVEL
        ch.setLevel(_stream_level)
        ch.setFormatter(fmt)
        self.logger.addHandler(ch)

    # ──────────────────────────────────────────
    # Connection management
    # ──────────────────────────────────────────

    def _get_xapi_url(self):
        host = self.config.host
        # NS: allow both bare hostname and full URL
        if not host.startswith('http'):
            host = f"https://{host}"
        return host

    def connect(self) -> bool:
        """Establish XAPI session to the XCP-ng pool master."""
        if not XENAPI_AVAILABLE:
            self.connection_error = 'XenAPI library not installed (pip install XenAPI)'
            self.logger.error(self.connection_error)
            return False

        with self._session_lock:
            try:
                url = self._get_xapi_url()
                session = XenAPI.Session(url, ignore_ssl=not self.config.ssl_verification)
                session.xenapi.login_with_password(
                    self.config.user, self.config.pass_,
                    '1.0', 'PegaProx'
                )
                self._session = session
                self.is_connected = True
                self.connection_error = None
                self.current_host = self.config.host
                self._consecutive_failures = 0
                self._last_keepalive = time.time()
                self.logger.info(f"Connected to XCP-ng pool: {self.config.host}")
                return True
            except Exception as e:
                self.is_connected = False
                self.connection_error = str(e)
                self._consecutive_failures += 1
                # only log first few failures
                if self._consecutive_failures <= 3:
                    self.logger.error(f"XAPI connect failed: {e}")
                return False

    # compat alias for API layer
    def connect_to_proxmox(self) -> bool:
        return self.connect()

    def disconnect(self):
        with self._session_lock:
            if self._session:
                try:
                    self._session.xenapi.session.logout()
                except Exception:
                    pass
                self._session = None
            self.is_connected = False
            self.logger.info("Disconnected from XCP-ng pool")

    def _keepalive(self):
        """Ping session to prevent timeout. XAPI sessions expire after ~24h idle."""
        now = time.time()
        if now - self._last_keepalive < 300:
            return
        try:
            self._session.xenapi.session.get_uuid(self._session._session)
            self._last_keepalive = now
        except Exception:
            self.logger.warning("XAPI session expired, reconnecting...")
            self.is_connected = False
            self.connect()

    def _api(self):
        """Get the xenapi proxy, reconnecting if needed."""
        if not self._session or not self.is_connected:
            if not self.connect():
                return None
        self._keepalive()
        return self._session.xenapi

    # ──────────────────────────────────────────
    # Start/stop background loop
    # ──────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True,
                                       name=f"xcpng-{self.id}")
        self.thread.start()
        self.logger.info("XCP-ng manager started")

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.disconnect()
        self.logger.info("XCP-ng manager stopped")

    def _run_loop(self):
        """Background loop - periodic status refresh & task polling."""
        # initial connect
        self.connect()
        while not self.stop_event.is_set():
            try:
                if self.is_connected:
                    self._refresh_cache()
                    self._poll_tasks()
                    self.last_run = datetime.now()
                    # MK: balance check on separate timer
                    now_t = time.time()
                    interval_cfg = getattr(self.config, 'check_interval', 300)
                    auto_migrate = getattr(self.config, 'auto_migrate', False)
                    if auto_migrate and now_t - self._last_balance_check >= interval_cfg:
                        try:
                            self.run_balance_check()
                        except Exception as be:
                            self.logger.error(f"[BALANCE] check error: {be}")
                        self._last_balance_check = now_t
                else:
                    # throttle reconnect attempts
                    now = time.time()
                    if now - self._last_reconnect_attempt > 30:
                        self._last_reconnect_attempt = now
                        self.connect()
            except Exception as e:
                self.logger.error(f"Loop error: {e}")

            interval = getattr(self.config, 'check_interval', 300)
            # NS: poll more often so tasks show up quickly
            self.stop_event.wait(min(interval, 15))

    # ──────────────────────────────────────────
    # Cache refresh
    # ──────────────────────────────────────────

    def _refresh_cache(self):
        """Pull fresh node/VM data from XAPI."""
        api = self._api()
        if not api:
            return

        now = time.time()
        if now - self._nodes_cache_time < self._nodes_cache_ttl:
            return

        try:
            self._cached_nodes = self._fetch_nodes(api)
            self._cached_vms = self._fetch_vms(api)
            self._nodes_cache_time = now
            self._vms_cache_time = now
            self._consecutive_failures = 0

            # collect metrics for predictive analysis
            for n in (self._cached_nodes or []):
                hostname = n.get('node', '')
                if not hostname:
                    continue
                maxmem = n.get('maxmem', 0)
                mem_used = n.get('mem', 0)
                cpu_frac = n.get('cpu', 0)
                snapshot = {
                    'ts': now,
                    'cpu': round(float(cpu_frac) * 100, 1) if cpu_frac == cpu_frac else 0,
                    'mem': round(mem_used / maxmem * 100, 1) if maxmem else 0,
                }
                hist = self._node_metrics_history[hostname]
                hist.append(snapshot)
                # cap at 1000 entries
                if len(hist) > 1000:
                    self._node_metrics_history[hostname] = hist[-1000:]
        except Exception as e:
            self.logger.error(f"Cache refresh failed: {e}")
            self._consecutive_failures += 1
            if self._consecutive_failures > 5:
                self.is_connected = False

    # ──────────────────────────────────────────
    # Nodes
    # ──────────────────────────────────────────

    def _fetch_nodes(self, api) -> list:
        host_refs = api.host.get_all()
        nodes = []
        for ref in host_refs:
            rec = api.host.get_record(ref)
            metrics_ref = rec.get('metrics', 'OpaqueRef:NULL')
            mem_total = 0
            mem_free = 0
            try:
                if metrics_ref != 'OpaqueRef:NULL':
                    m = api.host_metrics.get_record(metrics_ref)
                    mem_total = int(m.get('memory_total', 0))
                    mem_free = int(m.get('memory_free', 0))
            except Exception:
                pass

            cpu_count = len(rec.get('host_CPUs', []))

            # NS: query_data_source for live CPU avg (fraction 0-1)
            cpu_util = 0
            try:
                v = float(api.host.query_data_source(ref, 'cpu_avg'))
                if v == v:  # NaN check (nan != nan)
                    cpu_util = v
            except Exception:
                pass

            # uptime - try data source first, fallback to other_config boot_time
            uptime_secs = 0
            try:
                v = float(api.host.query_data_source(ref, 'uptime'))
                if v == v:
                    uptime_secs = int(v)
            except Exception:
                try:
                    bt = rec.get('other_config', {}).get('boot_time', '')
                    if bt:
                        uptime_secs = int(time.time() - float(bt))
                except Exception:
                    pass

            # network I/O - sum across physical interfaces
            netin = 0
            netout = 0
            for pif_ref in rec.get('PIFs', []):
                try:
                    dev = api.PIF.get_device(pif_ref)
                    if not dev:
                        continue
                    # bytes/sec from XAPI data source
                    rx = float(api.host.query_data_source(ref, f'pif_{dev}_rx'))
                    tx = float(api.host.query_data_source(ref, f'pif_{dev}_tx'))
                    if rx == rx: netin += max(0, rx)
                    if tx == tx: netout += max(0, tx)
                except Exception:
                    pass

            # load average from XAPI data source
            loadavg = None
            try:
                la = float(api.host.query_data_source(ref, 'loadavg'))
                if la == la:
                    loadavg = [round(la, 2)]
            except Exception:
                pass

            # software version for display
            sw_ver = rec.get('software_version', {})
            product_ver = sw_ver.get('product_version', '')
            product_brand = sw_ver.get('product_brand', 'XCP-ng')
            xen_ver = sw_ver.get('xen', '')

            # #419 follow-up: emit node netin/netout as bytes/sec rate to match the
            # post-#419 Proxmox contract on /api/clusters/<id>/metrics. NodeCard now
            # consumes a rate directly; the previous accumulator-to-counter dance is
            # no longer needed.
            hostname = _sanitize_str(rec.get('hostname', rec.get('name_label', '')))

            nodes.append({
                'node': hostname,
                # NS: enabled=false means maintenance in XAPI, not offline
                # if we got the record from XAPI the host is reachable
                'status': 'online',
                'id': _sanitize_str(rec.get('uuid', '')),
                'cpu': cpu_util,
                'maxcpu': cpu_count,
                'mem': mem_total - mem_free,
                'maxmem': mem_total,
                'uptime': uptime_secs,
                'netin': netin,
                'netout': netout,
                'type': 'node',
                '_enabled': rec.get('enabled', True),
                '_ref': ref,
                '_loadavg': loadavg,
                '_cpucount': cpu_count,
                '_product_version': f"{product_brand} {product_ver}" if product_ver else '',
                '_xen_version': xen_ver,
            })
        return nodes

    def get_nodes(self) -> list:
        if self._cached_nodes is not None:
            # strip internal fields
            return [{k: v for k, v in n.items() if not k.startswith('_')}
                    for n in self._cached_nodes]
        api = self._api()
        if not api:
            return []
        nodes = self._fetch_nodes(api)
        self._cached_nodes = nodes
        self._nodes_cache_time = time.time()
        return [{k: v for k, v in n.items() if not k.startswith('_')} for n in nodes]

    # ──────────────────────────────────────────
    # VMs
    # ──────────────────────────────────────────

    def _fetch_vms(self, api) -> list:
        db = get_db()
        vm_refs = api.VM.get_all()
        now = time.time()
        vms = []
        for ref in vm_refs:
            try:
                rec = api.VM.get_record(ref)
            except Exception:
                continue

            # skip templates, control domains, snapshots
            if rec.get('is_a_template', False):
                continue
            if rec.get('is_control_domain', False):
                continue
            if rec.get('is_a_snapshot', False):
                continue

            vm_uuid = rec.get('uuid', '')
            vmid = db.xcpng_get_vmid(self.id, vm_uuid)

            # figure out which host its on
            resident = rec.get('resident_on', 'OpaqueRef:NULL')
            node_name = ''
            if resident != 'OpaqueRef:NULL':
                try:
                    node_name = api.host.get_hostname(resident)
                except Exception:
                    pass

            power = rec.get('power_state', 'Halted')
            status = _POWER_STATE_MAP.get(power, 'unknown')

            vcpus = int(rec.get('VCPUs_at_startup', 0))
            vcpus_max = int(rec.get('VCPUs_max', 0))
            mem_max = int(rec.get('memory_dynamic_max', 0)) or int(rec.get('memory_static_max', 0))

            # MK: pull live stats from VM_metrics if VM is running
            cpu_frac = 0
            mem_actual = int(rec.get('memory_target', 0))
            vm_uptime = 0

            vm_metrics_ref = rec.get('metrics', 'OpaqueRef:NULL')
            if vm_metrics_ref != 'OpaqueRef:NULL' and power == 'Running':
                try:
                    vm_m = api.VM_metrics.get_record(vm_metrics_ref)
                    # average vCPU utilisation
                    utils = vm_m.get('VCPUs_utilisation', {})
                    if utils:
                        cpu_frac = sum(float(v) for v in utils.values()) / len(utils)
                    # actual memory consumption
                    ma = int(vm_m.get('memory_actual', 0))
                    if ma > 0:
                        mem_actual = ma
                    # uptime from start_time
                    st = vm_m.get('start_time')
                    if st:
                        try:
                            # XAPI returns xmlrpc DateTime - str gives ISO-ish
                            from datetime import datetime as _dt
                            started = _dt.fromisoformat(str(st).replace('T', ' ').split('.')[0])
                            vm_uptime = max(0, int(now - started.timestamp()))
                        except Exception:
                            pass
                except Exception:
                    pass

            # disk size - sum of VBDs -> VDIs
            disk_total = 0
            for vbd_ref in rec.get('VBDs', []):
                try:
                    vbd_rec = api.VBD.get_record(vbd_ref)
                    if vbd_rec.get('type') == 'Disk':
                        vdi_ref = vbd_rec.get('VDI', 'OpaqueRef:NULL')
                        if vdi_ref != 'OpaqueRef:NULL':
                            vdi_size = int(api.VDI.get_virtual_size(vdi_ref))
                            disk_total += vdi_size
                except Exception:
                    pass

            # guest metrics for IP addresses (cheap XAPI call)
            guest_ips = []
            gm_ref = rec.get('guest_metrics', 'OpaqueRef:NULL')
            if gm_ref != 'OpaqueRef:NULL' and power == 'Running':
                try:
                    gm_nets = api.VM_guest_metrics.get_networks(gm_ref)
                    _seen = set()
                    for gk, gv in gm_nets.items():
                        if '/ip' in gk and gv not in _seen:
                            _seen.add(gv)
                            guest_ips.append(gv)
                except Exception:
                    pass

            vms.append({
                'vmid': vmid,
                'name': _sanitize_str(rec.get('name_label', '')),
                'status': status,
                'type': 'qemu',  # XCP-ng only has HVM/PV VMs, map to 'qemu' for compat
                'node': _sanitize_str(node_name),
                'cpu': cpu_frac,
                'maxcpu': vcpus_max or vcpus,
                'mem': mem_actual,
                'maxmem': mem_max,
                'disk': 0,
                'maxdisk': disk_total,
                'uptime': vm_uptime,
                'netin': 0,
                'netout': 0,
                'template': '',
                'tags': [],
                'lock': '',
                'uuid': vm_uuid,
                'ip_addresses': guest_ips,
                '_ref': ref,
            })
        return vms

    def get_vms(self, node=None) -> list:
        if self._cached_vms is not None:
            vms = self._cached_vms
        else:
            api = self._api()
            if not api:
                return []
            vms = self._fetch_vms(api)
            self._cached_vms = vms
            self._vms_cache_time = time.time()

        result = [{k: v for k, v in vm.items() if not k.startswith('_')} for vm in vms]
        if node:
            result = [vm for vm in result if vm.get('node') == node]
        return result

    # ──────────────────────────────────────────
    # Storage
    # ──────────────────────────────────────────

    def get_storages(self, node=None) -> list:
        api = self._api()
        if not api:
            return []
        try:
            sr_refs = api.SR.get_all()
            storages = []
            for ref in sr_refs:
                rec = api.SR.get_record(ref)
                sr_type = rec.get('type', '')
                # skip internal/udev SRs
                if sr_type in ('udev', 'iso'):
                    continue
                total = int(rec.get('physical_size', 0))
                used = int(rec.get('physical_utilisation', 0))
                storages.append({
                    'storage': _sanitize_str(rec.get('name_label', '')),
                    'type': sr_type,
                    'total': total,
                    'used': used,
                    'avail': total - used if total > used else 0,
                    'status': 'available',
                    'shared': bool(rec.get('shared', False)),
                    'content': 'images',
                    'uuid': rec.get('uuid', ''),
                })
            return storages
        except Exception as e:
            self.logger.error(f"get_storages failed: {e}")
            return []

    # ──────────────────────────────────────────
    # Networks
    # ──────────────────────────────────────────

    def get_networks(self, node=None) -> list:
        api = self._api()
        if not api:
            return []
        try:
            net_refs = api.network.get_all()
            nets = []
            for ref in net_refs:
                rec = api.network.get_record(ref)
                # LW: skip internal xapi networks
                if rec.get('name_label', '').startswith('xapi'):
                    continue
                nets.append({
                    'iface': _sanitize_str(rec.get('bridge', rec.get('name_label', ''))),
                    'type': 'bridge',
                    'active': True,
                    'name': _sanitize_str(rec.get('name_label', '')),
                    'uuid': rec.get('uuid', ''),
                })
            return nets
        except Exception as e:
            self.logger.error(f"get_networks failed: {e}")
            return []

    # ──────────────────────────────────────────
    # Cluster status (for dashboard aggregation)
    # ──────────────────────────────────────────

    def get_cluster_status(self) -> dict:
        nodes = self.get_nodes()
        vms = self.get_vms()
        total_cpu = sum(n.get('maxcpu', 0) for n in nodes)
        total_mem = sum(n.get('maxmem', 0) for n in nodes)
        used_mem = sum(n.get('mem', 0) for n in nodes)
        running_vms = len([v for v in vms if v.get('status') == 'running'])
        return {
            'nodes': len(nodes),
            'vms': len(vms),
            'running_vms': running_vms,
            'total_cpu': total_cpu,
            'total_mem': total_mem,
            'used_mem': used_mem,
            'cluster_type': 'xcpng',
        }

    def test_connection(self) -> bool:
        return self.connect()

    # ──────────────────────────────────────────
    # SSE broadcast compat (same shape as PegaProxManager)
    # ──────────────────────────────────────────

    def get_node_status(self) -> dict:
        """Return node metrics keyed by hostname - used by broadcast loop.

        Must match PegaProxManager.get_node_status() output format so the
        frontend doesn't need cluster_type-specific rendering.
        """
        nodes = self._cached_nodes
        if nodes is None:
            nodes = self.get_nodes()
            # get_nodes strips _ref, re-fetch from cache
            nodes = self._cached_nodes or []

        result = {}
        for n in nodes:
            name = n.get('node', '')
            maxmem = n.get('maxmem', 0)
            mem_used = n.get('mem', 0)
            cpu_frac = n.get('cpu', 0) or 0  # guard against NaN/None
            mem_pct = round(mem_used / maxmem * 100, 1) if maxmem else 0
            cpu_pct = round(cpu_frac * 100, 1) if cpu_frac == cpu_frac else 0
            cpucount = n.get('_cpucount', n.get('maxcpu', 0))
            result[name] = {
                'status': n.get('status', 'unknown'),
                'cpu_percent': cpu_pct,
                'mem_used': mem_used,
                'mem_total': maxmem,
                'mem_percent': mem_pct,
                'disk_used': None,   # XAPI doesn't expose dom0 rootfs
                'disk_total': None,
                'disk_percent': None,
                'netin': n.get('netin', 0),
                'netout': n.get('netout', 0),
                'uptime': n.get('uptime', 0),
                'score': cpu_pct + mem_pct,
                'loadavg': n.get('_loadavg'),
                'cpuinfo': {'cores': cpucount, 'sockets': 1} if cpucount else None,
                'pveversion': n.get('_product_version', ''),
                'maintenance_mode': name in self.nodes_in_maintenance or not n.get('_enabled', True),
                'offline': n.get('status') != 'online',
            }
        return result

    def get_vm_resources(self) -> list:
        """Return VM+node list for broadcast loop - same format as Proxmox /cluster/resources.
        MK: include nodes so SSE doesn't think connection is stale when cluster has zero VMs."""
        vms = self.get_vms() or []
        nodes = self.get_nodes() or []
        return vms + nodes

    # ──────────────────────────────────────────
    # VM Lifecycle
    # ──────────────────────────────────────────

    def _resolve_vm(self, vmid):
        """Resolve a VMID (int or str) to XAPI VM ref."""
        db = get_db()
        vm_uuid = db.xcpng_resolve_vmid(self.id, vmid)
        if not vm_uuid:
            raise ValueError(f"Unknown VMID {vmid} for cluster {self.id}")
        api = self._api()
        if not api:
            raise ConnectionError("Not connected to XCP-ng")
        return api.VM.get_by_uuid(vm_uuid)

    def start_vm(self, node, vmid, vm_type='qemu') -> str:
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            # start paused=False, force=False
            task_ref = api.Async.VM.start(ref, False, False)
            task_id = self._track_task(task_ref, 'start_vm', vmid)
            self.logger.info(f"Starting VM {vmid}")
            return task_id
        except Exception as e:
            self.logger.error(f"start_vm {vmid}: {e}")
            return None

    def stop_vm(self, node, vmid, vm_type='qemu') -> str:
        """Hard shutdown."""
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            task_ref = api.Async.VM.hard_shutdown(ref)
            return self._track_task(task_ref, 'stop_vm', vmid)
        except Exception as e:
            self.logger.error(f"stop_vm {vmid}: {e}")
            return None

    def shutdown_vm(self, node, vmid, vm_type='qemu') -> str:
        """Clean shutdown (ACPI)."""
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            task_ref = api.Async.VM.clean_shutdown(ref)
            return self._track_task(task_ref, 'shutdown_vm', vmid)
        except Exception as e:
            self.logger.error(f"shutdown_vm {vmid}: {e}")
            return None

    def reboot_vm(self, node, vmid) -> str:
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            task_ref = api.Async.VM.clean_reboot(ref)
            return self._track_task(task_ref, 'reboot_vm', vmid)
        except Exception as e:
            self.logger.error(f"reboot_vm {vmid}: {e}")
            return None

    def suspend_vm(self, node, vmid, vm_type='qemu') -> str:
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            task_ref = api.Async.VM.suspend(ref)
            return self._track_task(task_ref, 'suspend_vm', vmid)
        except Exception as e:
            self.logger.error(f"suspend_vm {vmid}: {e}")
            return None

    def resume_vm(self, node, vmid, vm_type='qemu') -> str:
        api = self._api()
        if not api:
            return None
        try:
            ref = self._resolve_vm(vmid)
            # start_paused=False, force=False
            task_ref = api.Async.VM.resume(ref, False, False)
            return self._track_task(task_ref, 'resume_vm', vmid)
        except Exception as e:
            self.logger.error(f"resume_vm {vmid}: {e}")
            return None

    def delete_vm(self, node, vmid, vm_type='qemu', purge=False, destroy_unreferenced=False) -> dict:
        api = self._api()
        if not api:
            return {'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            # must be halted to destroy
            power = api.VM.get_power_state(ref)
            if power != 'Halted':
                api.VM.hard_shutdown(ref)
                # wait briefly
                time.sleep(2)

            # destroy associated VDIs if purge
            if purge:
                vbds = api.VM.get_VBDs(ref)
                for vbd_ref in vbds:
                    try:
                        vbd_rec = api.VBD.get_record(vbd_ref)
                        if vbd_rec.get('type') == 'Disk':
                            vdi_ref = vbd_rec.get('VDI', 'OpaqueRef:NULL')
                            if vdi_ref != 'OpaqueRef:NULL':
                                api.VDI.destroy(vdi_ref)
                    except Exception as e:
                        self.logger.warning(f"Failed to destroy VDI: {e}")

            api.VM.destroy(ref)

            # cleanup vmid mapping
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute('DELETE FROM xcpng_vmid_map WHERE cluster_id = ? AND vmid = ?',
                          (self.id, int(vmid)))
            db.conn.commit()

            # invalidate cache
            self._cached_vms = None
            self.logger.info(f"Destroyed VM {vmid}")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"delete_vm {vmid} failed: {e}")
            return {'error': str(e)}

    def clone_vm(self, node, vmid, vm_type='qemu', newid=None, name=None, **kwargs) -> dict:
        api = self._api()
        if not api:
            return {'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            clone_name = name or f"clone-of-{vmid}"
            new_ref = api.VM.clone(ref, clone_name)
            new_uuid = api.VM.get_uuid(new_ref)
            db = get_db()
            new_vmid = db.xcpng_get_vmid(self.id, new_uuid)
            self._cached_vms = None
            self.logger.info(f"Cloned VM {vmid} -> {new_vmid} ({clone_name})")
            return {'success': True, 'vmid': new_vmid}
        except Exception as e:
            self.logger.error(f"clone_vm {vmid} failed: {e}")
            return {'error': str(e)}

    def migrate_vm(self, node, vmid, vm_type='qemu', target_node=None, online=True, options=None):
        """Legacy migrate interface (used by auto-balancer). Delegates to migrate_vm_manual."""
        return self.migrate_vm_manual(node, vmid, vm_type, target_node, online, options)

    def migrate_vm_manual(self, node, vmid, vm_type='qemu', target_node=None,
                          online=True, options=None) -> dict:
        """Migrate VM to another host in the XCP-ng pool.

        NS Mar 2026 - pool_migrate for live, shutdown+start for offline.
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected to XCP-ng'}

        if not target_node:
            return {'success': False, 'error': 'Target node is required'}

        try:
            vm_ref = self._resolve_vm(vmid)
            power = api.VM.get_power_state(vm_ref)

            # find target host ref by hostname
            target_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == target_node:
                    target_ref = href
                    break

            if not target_ref:
                return {'success': False, 'error': f'Host {target_node} not found in pool'}

            # check target is enabled
            if not api.host.get_enabled(target_ref):
                return {'success': False, 'error': f'Host {target_node} is disabled/maintenance'}

            if online and power == 'Running':
                # live migration within same pool
                # MK: options dict is empty for XCP-ng, we just pass the standard XAPI migrate opts
                migrate_opts = {'force': 'true'}  # xenapi wants string bools
                task_ref = api.Async.VM.pool_migrate(vm_ref, target_ref, migrate_opts)
                task_id = self._track_task(task_ref, 'migrate_vm', vmid)
                self.logger.info(f"Live migrating VM {vmid} -> {target_node}")
            elif power == 'Halted':
                # offline: just set affinity + start on target
                api.VM.set_affinity(vm_ref, target_ref)
                task_ref = api.Async.VM.start_on(vm_ref, target_ref, False, False)
                task_id = self._track_task(task_ref, 'migrate_vm', vmid)
                self.logger.info(f"Cold migrating VM {vmid} -> {target_node} (start_on)")
            else:
                # suspended/paused -> shut down first, then move
                api.VM.hard_shutdown(vm_ref)
                time.sleep(2)
                api.VM.set_affinity(vm_ref, target_ref)
                task_ref = api.Async.VM.start_on(vm_ref, target_ref, False, False)
                task_id = self._track_task(task_ref, 'migrate_vm', vmid)
                self.logger.info(f"Migrate VM {vmid} -> {target_node} (shutdown + start_on)")

            self._cached_vms = None
            return {'success': True, 'task': task_id}
        except Exception as e:
            self.logger.error(f"migrate_vm {vmid} -> {target_node}: {e}")
            return {'success': False, 'error': str(e)}

    def _get_templates(self, api) -> list:
        """Fetch available VM templates from pool."""
        templates = []
        for ref in api.VM.get_all():
            try:
                rec = api.VM.get_record(ref)
                if rec.get('is_a_template') and not rec.get('is_control_domain'):
                    templates.append({
                        'uuid': rec.get('uuid', ''),
                        'name': rec.get('name_label', ''),
                        'description': rec.get('name_description', ''),
                        '_ref': ref,
                    })
            except Exception:
                pass
        return templates

    def get_templates(self, node=None) -> list:
        """List VM templates. node param ignored (XCP-ng templates are pool-wide)."""
        api = self._api()
        if not api:
            return []
        tpls = self._get_templates(api)
        return [{k: v for k, v in t.items() if not k.startswith('_')} for t in tpls]

    def create_vm(self, node, vm_config) -> dict:
        """Create VM on XCP-ng - from template, ISO, or PXE.

        vm_config keys:
          install_method - 'template' (default), 'iso', or 'pxe'
          template   - UUID or name of source template (required for template method)
          name       - VM name (required)
          os_type    - OS type key for built-in template selection (iso/pxe)
          iso_uuid   - VDI UUID of ISO to boot from (iso method)
          disk_size  - disk size in GB (iso/pxe method)
          vcpus      - number of vCPUs
          memory     - RAM in bytes (or int with 'G' suffix stripped)
          sr         - target SR UUID for disk provisioning
          network    - network UUID or bridge name to attach
          start      - bool, start VM after creation
          description - optional description
        """
        install_method = vm_config.get('install_method', 'template')
        if install_method in ('iso', 'pxe'):
            return self._create_vm_from_scratch(node, vm_config)

        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected to XCP-ng'}

        tpl_ident = vm_config.get('template', '')
        vm_name = _sanitize_str(vm_config.get('name', ''))

        if not tpl_ident:
            return {'success': False, 'error': 'Template UUID or name is required'}
        if not vm_name:
            return {'success': False, 'error': 'VM name is required'}

        try:
            # resolve template - try UUID first, then name_label
            tpl_ref = None
            try:
                tpl_ref = api.VM.get_by_uuid(tpl_ident)
            except Exception:
                # not a UUID, search by name
                refs = api.VM.get_by_name_label(tpl_ident)
                for r in refs:
                    if api.VM.get_is_a_template(r):
                        tpl_ref = r
                        break

            if not tpl_ref:
                return {'success': False, 'error': f'Template not found: {tpl_ident}'}

            # NS: security - verify it IS actually a template, not a regular VM someone
            # is trying to clone through the create endpoint
            if not api.VM.get_is_a_template(tpl_ref):
                return {'success': False, 'error': 'Specified VM is not a template'}

            # clone from template
            new_ref = api.VM.clone(tpl_ref, vm_name)

            # provision (instantiates template disks on default SR)
            api.VM.provision(new_ref)

            # description
            desc = vm_config.get('description', '')
            if desc:
                api.VM.set_name_description(new_ref, _sanitize_str(desc))

            # vCPUs
            vcpus = vm_config.get('vcpus')
            if vcpus:
                vcpus = int(vcpus)
                if vcpus < 1 or vcpus > 256:
                    self.logger.warning(f"create_vm: vcpus {vcpus} out of range, clamping")
                    vcpus = max(1, min(vcpus, 256))
                api.VM.set_VCPUs_max(new_ref, str(vcpus))
                api.VM.set_VCPUs_at_startup(new_ref, str(vcpus))

            # memory - accept bytes or string with G suffix
            memory = vm_config.get('memory')
            if memory:
                mem_bytes = int(str(memory).replace('G', '').replace('g', ''))
                # if value looks like GB (< 1024), convert
                if mem_bytes < 4096:
                    mem_bytes = mem_bytes * 1024 * 1024 * 1024
                if mem_bytes < 128 * 1024 * 1024:  # min 128MB
                    mem_bytes = 128 * 1024 * 1024
                s = str(mem_bytes)
                api.VM.set_memory_limits(new_ref, s, s, s, s)

            # target SR - move VDIs if different from template default
            target_sr = vm_config.get('sr')
            if target_sr:
                self._move_vm_disks_to_sr(api, new_ref, target_sr)

            # network - attach VIF to specified network
            net_ident = vm_config.get('network')
            if net_ident:
                self._attach_network(api, new_ref, net_ident)

            # register VMID
            new_uuid = api.VM.get_uuid(new_ref)
            db = get_db()
            new_vmid = db.xcpng_get_vmid(self.id, new_uuid)

            self.logger.info(f"Created VM {new_vmid} ({vm_name}) from template {tpl_ident}")

            # optionally start
            if vm_config.get('start'):
                try:
                    api.Async.VM.start(new_ref, False, False)
                except Exception as e:
                    self.logger.warning(f"Auto-start after create failed: {e}")

            self._cached_vms = None
            return {'success': True, 'vmid': new_vmid, 'uuid': new_uuid}
        except Exception as e:
            self.logger.error(f"create_vm failed: {e}")
            return {'success': False, 'error': str(e)}

    def _create_vm_from_scratch(self, node, vm_config):
        """Create VM from built-in template + ISO boot or PXE.

        MK Mar 2026 - cloning built-in templates is more reliable than VM.create()
        because XAPI sets platform flags (ACPI, PAE, viridian for Windows) automatically.
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected to XCP-ng'}

        vm_name = _sanitize_str(vm_config.get('name', ''))
        if not vm_name:
            return {'success': False, 'error': 'VM name is required'}

        method = vm_config.get('install_method', 'iso')
        os_type = vm_config.get('os_type', 'linux')
        tpl_name = self._OS_TEMPLATE_MAP.get(os_type, 'Other install media')

        try:
            # find built-in template by name_label
            builtin_ref = None
            for ref in api.VM.get_all():
                try:
                    rec = api.VM.get_record(ref)
                    if not rec.get('is_a_template'):
                        continue
                    # built-in templates have empty other_config['default_template'] or are
                    # simply the ones that ship with XCP-ng - match by name
                    if rec.get('name_label') == tpl_name:
                        builtin_ref = ref
                        break
                except Exception:
                    continue

            if not builtin_ref:
                # fallback: try 'Other install media' if specific template missing
                if tpl_name != 'Other install media':
                    self.logger.warning(f"Template '{tpl_name}' not found, falling back to 'Other install media'")
                    for ref in api.VM.get_all():
                        try:
                            rec = api.VM.get_record(ref)
                            if rec.get('is_a_template') and rec.get('name_label') == 'Other install media':
                                builtin_ref = ref
                                break
                        except Exception:
                            continue
                if not builtin_ref:
                    return {'success': False, 'error': f'Built-in template not found: {tpl_name}'}

            # clone + unmark as template
            new_ref = api.VM.clone(builtin_ref, vm_name)
            api.VM.set_is_a_template(new_ref, False)

            # clean up template disk specs
            try:
                api.VM.remove_from_other_config(new_ref, 'disks')
            except Exception:
                pass  # might not exist

            # remove template VBDs+VDIs (we create our own disk)
            for vbd_ref in api.VM.get_VBDs(new_ref):
                try:
                    vbd_rec = api.VBD.get_record(vbd_ref)
                    vdi = vbd_rec.get('VDI', 'OpaqueRef:NULL')
                    api.VBD.destroy(vbd_ref)
                    if vdi != 'OpaqueRef:NULL':
                        api.VDI.destroy(vdi)
                except Exception:
                    pass

            # description
            desc = vm_config.get('description', '')
            if desc:
                api.VM.set_name_description(new_ref, _sanitize_str(desc))

            # vCPUs
            vcpus = vm_config.get('vcpus')
            if vcpus:
                vc = max(1, min(int(vcpus), 256))
                api.VM.set_VCPUs_max(new_ref, str(vc))
                api.VM.set_VCPUs_at_startup(new_ref, str(vc))

            # memory
            memory = vm_config.get('memory')
            if memory:
                mem_bytes = int(str(memory).replace('G', '').replace('g', ''))
                if mem_bytes < 4096:
                    mem_bytes *= 1024 * 1024 * 1024
                mem_bytes = max(mem_bytes, 128 * 1024 * 1024)
                s = str(mem_bytes)
                api.VM.set_memory_limits(new_ref, s, s, s, s)

            # find target SR for the new disk
            target_sr_uuid = vm_config.get('sr')
            target_sr = None
            if target_sr_uuid:
                target_sr = api.SR.get_by_uuid(target_sr_uuid)
            else:
                # use pool default SR
                pool_refs = api.pool.get_all()
                if pool_refs:
                    default_sr = api.pool.get_default_SR(pool_refs[0])
                    if default_sr and default_sr != 'OpaqueRef:NULL':
                        target_sr = default_sr

            if not target_sr:
                # last resort: pick first non-ISO SR
                for sr_ref in api.SR.get_all():
                    sr_type = api.SR.get_type(sr_ref)
                    if sr_type not in ('iso', 'udev', 'cd'):
                        target_sr = sr_ref
                        break

            # create new VDI on target SR
            disk_gb = int(vm_config.get('disk_size', 32))
            disk_bytes = disk_gb * 1024 * 1024 * 1024
            vdi_rec = {
                'name_label': f'{vm_name} disk 0',
                'name_description': 'Created by PegaProx',
                'SR': target_sr,
                'virtual_size': str(disk_bytes),
                'type': 'user',
                'sharable': False,
                'read_only': False,
                'other_config': {},
            }
            new_vdi = api.VDI.create(vdi_rec)

            # attach disk as VBD
            vbd_rec = {
                'VM': new_ref,
                'VDI': new_vdi,
                'userdevice': '0',
                'bootable': True,
                'mode': 'RW',
                'type': 'Disk',
                'empty': False,
                'other_config': {},
                'qos_algorithm_type': '',
                'qos_algorithm_params': {},
            }
            api.VBD.create(vbd_rec)

            if method == 'iso':
                iso_uuid = vm_config.get('iso_uuid', '')
                if iso_uuid:
                    iso_vdi = api.VDI.get_by_uuid(iso_uuid)
                    cd_rec = {
                        'VM': new_ref,
                        'VDI': iso_vdi,
                        'userdevice': '3',
                        'bootable': False,
                        'mode': 'RO',
                        'type': 'CD',
                        'empty': False,
                        'other_config': {},
                        'qos_algorithm_type': '',
                        'qos_algorithm_params': {},
                    }
                    api.VBD.create(cd_rec)
                # boot order: cdrom first, then disk
                boot_order = vm_config.get('boot_order', 'dc')
                api.VM.set_HVM_boot_params(new_ref, {'order': boot_order})
            elif method == 'pxe':
                # network boot
                api.VM.set_HVM_boot_params(new_ref, {'order': 'n'})

            api.VM.set_HVM_boot_policy(new_ref, 'BIOS order')

            # network
            net_ident = vm_config.get('network')
            if net_ident:
                self._attach_network(api, new_ref, net_ident)

            new_uuid = api.VM.get_uuid(new_ref)
            db = get_db()
            new_vmid = db.xcpng_get_vmid(self.id, new_uuid)

            self.logger.info(f"Created VM {new_vmid} ({vm_name}) via {method}, os_type={os_type}")

            if vm_config.get('start'):
                try:
                    api.Async.VM.start(new_ref, False, False)
                except Exception as e:
                    self.logger.warning(f"auto-start failed for new VM: {e}")

            self._cached_vms = None
            return {'success': True, 'vmid': new_vmid, 'uuid': new_uuid}
        except Exception as e:
            self.logger.error(f"_create_vm_from_scratch failed: {e}")
            return {'success': False, 'error': str(e)}

    def get_os_types(self):
        """Available OS types for the 'from scratch' VM creation wizard."""
        return [
            {'key': 'linux', 'label': 'Linux (Generic)'},
            {'key': 'ubuntu', 'label': 'Ubuntu'},
            {'key': 'debian', 'label': 'Debian'},
            {'key': 'centos', 'label': 'CentOS / Rocky'},
            {'key': 'rhel', 'label': 'Red Hat Enterprise Linux'},
            {'key': 'sles', 'label': 'SUSE Linux Enterprise'},
            {'key': 'windows', 'label': 'Windows 10 / Server'},
            {'key': 'windows11', 'label': 'Windows 11'},
            {'key': 'other', 'label': 'Other'},
        ]

    def _move_vm_disks_to_sr(self, api, vm_ref, target_sr_uuid):
        """Move all VDIs of a VM to a different SR. Used during template-based creation."""
        try:
            target_sr = api.SR.get_by_uuid(target_sr_uuid)
        except Exception:
            self.logger.warning(f"Target SR {target_sr_uuid} not found, skipping disk move")
            return

        for vbd_ref in api.VM.get_VBDs(vm_ref):
            try:
                rec = api.VBD.get_record(vbd_ref)
                if rec.get('type') != 'Disk':
                    continue
                vdi_ref = rec.get('VDI', 'OpaqueRef:NULL')
                if vdi_ref == 'OpaqueRef:NULL':
                    continue
                # check if already on target
                current_sr = api.VDI.get_SR(vdi_ref)
                if current_sr == target_sr:
                    continue
                api.VDI.pool_migrate(vdi_ref, target_sr, {})
            except Exception as e:
                # LW: non-fatal, disk stays on original SR
                self.logger.warning(f"Failed to move VDI to target SR: {e}")

    def _attach_network(self, api, vm_ref, net_ident):
        """Attach a VIF to the VM for the specified network."""
        net_ref = None
        try:
            net_ref = api.network.get_by_uuid(net_ident)
        except Exception:
            # try by bridge name or label
            for nref in api.network.get_all():
                rec = api.network.get_record(nref)
                if rec.get('bridge') == net_ident or rec.get('name_label') == net_ident:
                    net_ref = nref
                    break

        if not net_ref:
            self.logger.warning(f"Network {net_ident} not found, skipping VIF attach")
            return

        # find next available device index
        existing_vifs = api.VM.get_VIFs(vm_ref)
        used_devices = set()
        for vif_ref in existing_vifs:
            try:
                used_devices.add(int(api.VIF.get_device(vif_ref)))
            except Exception:
                pass
        device = str(next(i for i in range(10) if i not in used_devices))

        vif_record = {
            'VM': vm_ref,
            'network': net_ref,
            'device': device,
            'MTU': '1500',
            'MAC': '',  # auto-generate
            'other_config': {},
            'qos_algorithm_type': '',
            'qos_algorithm_params': {},
        }
        api.VIF.create(vif_record)

    # ──────────────────────────────────────────
    # VM Config
    # ──────────────────────────────────────────

    def get_vm_config(self, node, vmid, vm_type='qemu') -> dict:
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            rec = api.VM.get_record(ref)

            # build disk list from VBDs
            disks = []
            cdroms = []
            for vbd_ref in rec.get('VBDs', []):
                try:
                    vbd = api.VBD.get_record(vbd_ref)
                    if vbd.get('type') == 'CD':
                        cd_info = {'device': vbd.get('userdevice', ''), 'empty': vbd.get('empty', True)}
                        if not vbd.get('empty') and vbd.get('VDI') != 'OpaqueRef:NULL':
                            cd_info['iso'] = api.VDI.get_name_label(vbd['VDI'])
                        cdroms.append(cd_info)
                    elif vbd.get('type') == 'Disk' and vbd.get('VDI') != 'OpaqueRef:NULL':
                        vdi = api.VDI.get_record(vbd['VDI'])
                        disks.append({
                            'id': vbd.get('userdevice', ''),
                            'size': int(vdi.get('virtual_size', 0)),
                            'used': int(vdi.get('physical_utilisation', 0)),
                            'storage': api.SR.get_name_label(vdi.get('SR', 'OpaqueRef:NULL')),
                            'name': vdi.get('name_label', ''),
                            'uuid': vdi.get('uuid', ''),
                            'bootable': vbd.get('bootable', False),
                        })
                except Exception:
                    pass

            # network interfaces from VIFs
            nets = []
            for vif_ref in rec.get('VIFs', []):
                try:
                    vif = api.VIF.get_record(vif_ref)
                    net_label = api.network.get_name_label(vif.get('network', 'OpaqueRef:NULL'))
                    bridge = api.network.get_bridge(vif.get('network', 'OpaqueRef:NULL'))
                    nets.append({
                        'id': vif.get('device', ''),
                        'mac': vif.get('MAC', ''),
                        'network': net_label,
                        'bridge': bridge,
                        'mtu': vif.get('MTU', '1500'),
                    })
                except Exception:
                    pass

            config = {
                'name': rec.get('name_label', ''),
                'description': rec.get('name_description', ''),
                'memory': int(rec.get('memory_static_max', 0)),
                'vcpus': int(rec.get('VCPUs_max', 0)),
                'vcpus_at_startup': int(rec.get('VCPUs_at_startup', 0)),
                'power_state': rec.get('power_state', ''),
                'os_version': rec.get('os_version', {}),
                'platform': rec.get('platform', {}),
                'uuid': rec.get('uuid', ''),
                'disks': disks,
                'cdroms': cdroms,
                'networks': nets,
                'boot_params': rec.get('PV_args', ''),
                'ha_restart_priority': rec.get('ha_restart_priority', ''),
            }
            return {'success': True, 'config': config}
        except Exception as e:
            self.logger.error(f"get_vm_config {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def update_vm_config(self, node, vmid, vm_type='qemu', config_updates=None):
        """Update XCP-ng VM configuration.

        Supported config_updates keys:
          name        - VM name (name_label)
          description - VM description
          vcpus       - vCPU count (hot-add if within VCPUs_max, else needs shutdown)
          memory      - RAM in bytes
        """
        if not config_updates:
            return {'success': True, 'message': 'Nothing to update'}

        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected to XCP-ng'}

        try:
            ref = self._resolve_vm(vmid)
            power = api.VM.get_power_state(ref)
            changed = []

            # name
            if 'name' in config_updates:
                new_name = _sanitize_str(config_updates['name'])
                if new_name:
                    api.VM.set_name_label(ref, new_name)
                    changed.append('name')

            if 'description' in config_updates:
                api.VM.set_name_description(ref, _sanitize_str(config_updates['description']))
                changed.append('description')

            # vCPUs
            if 'vcpus' in config_updates:
                vcpus = int(config_updates['vcpus'])
                if vcpus < 1:
                    vcpus = 1
                current_max = int(api.VM.get_VCPUs_max(ref))

                if power == 'Running':
                    if vcpus <= current_max:
                        # hot-change within max - XAPI allows this live
                        api.VM.set_VCPUs_number_live(ref, str(vcpus))
                        changed.append(f'vcpus={vcpus} (live)')
                    else:
                        return {'success': False,
                                'error': f'Cannot hot-add beyond VCPUs_max ({current_max}). '
                                         f'Shut down VM first or increase VCPUs_max while halted.'}
                else:
                    # halted - can change both max and startup
                    api.VM.set_VCPUs_max(ref, str(vcpus))
                    api.VM.set_VCPUs_at_startup(ref, str(vcpus))
                    changed.append(f'vcpus={vcpus}')

            # memory
            if 'memory' in config_updates:
                mem = int(str(config_updates['memory']).replace('G', '').replace('g', ''))
                if mem < 4096:
                    mem = mem * 1024 * 1024 * 1024
                if mem < 128 * 1024 * 1024:
                    mem = 128 * 1024 * 1024
                s = str(mem)

                if power == 'Running':
                    # dynamic range only when running
                    try:
                        api.VM.set_memory_dynamic_range(ref, s, s)
                        changed.append('memory (dynamic)')
                    except Exception as e:
                        # some XCP-ng builds don't support dynamic range change
                        return {'success': False, 'error': f'Cannot change memory while running: {e}'}
                else:
                    api.VM.set_memory_limits(ref, s, s, s, s)
                    changed.append('memory')

            if not changed:
                return {'success': True, 'message': 'No recognized config keys to update'}

            self._cached_vms = None
            self.logger.info(f"VM {vmid} config updated: {', '.join(changed)}")
            return {'success': True, 'message': f'Configuration updated ({", ".join(changed)})'}
        except ValueError as e:
            return {'success': False, 'error': f'Invalid value: {e}'}
        except Exception as e:
            self.logger.error(f"update_vm_config {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # Snapshots
    # ──────────────────────────────────────────

    def get_snapshots(self, node, vmid, vm_type='qemu') -> list:
        api = self._api()
        if not api:
            return []
        try:
            ref = self._resolve_vm(vmid)
            snap_refs = api.VM.get_snapshots(ref)
            snaps = []
            for sref in snap_refs:
                rec = api.VM.get_record(sref)
                snaps.append({
                    'name': rec.get('name_label', ''),
                    'description': rec.get('name_description', ''),
                    'snaptime': rec.get('snapshot_time', {}).get('value', '') if isinstance(rec.get('snapshot_time'), dict) else str(rec.get('snapshot_time', '')),
                    'uuid': rec.get('uuid', ''),
                })
            return snaps
        except Exception as e:
            self.logger.error(f"get_snapshots {vmid}: {e}")
            return []

    def create_snapshot(self, node, vmid, vm_type='qemu', snapname='', description='', vmstate=False):
        api = self._api()
        if not api:
            return {'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            snap_ref = api.VM.snapshot(ref, snapname)
            if description:
                api.VM.set_name_description(snap_ref, description)
            self.logger.info(f"Created snapshot '{snapname}' for VM {vmid}")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"create_snapshot {vmid}: {e}")
            return {'error': str(e)}

    def delete_snapshot(self, node, vmid, vm_type='qemu', snapname=''):
        api = self._api()
        if not api:
            return {'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            snap_refs = api.VM.get_snapshots(ref)
            for sref in snap_refs:
                if api.VM.get_name_label(sref) == snapname:
                    api.VM.destroy(sref)
                    self.logger.info(f"Deleted snapshot '{snapname}' for VM {vmid}")
                    return {'success': True}
            return {'error': f'Snapshot {snapname} not found'}
        except Exception as e:
            self.logger.error(f"delete_snapshot {vmid}: {e}")
            return {'error': str(e)}

    def rollback_snapshot(self, node, vmid, vm_type='qemu', snapname=''):
        api = self._api()
        if not api:
            return {'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            snap_refs = api.VM.get_snapshots(ref)
            for sref in snap_refs:
                if api.VM.get_name_label(sref) == snapname:
                    api.VM.revert(sref)
                    self.logger.info(f"Reverted VM {vmid} to snapshot '{snapname}'")
                    return {'success': True}
            return {'error': f'Snapshot {snapname} not found'}
        except Exception as e:
            self.logger.error(f"rollback_snapshot {vmid}: {e}")
            return {'error': str(e)}

    # ──────────────────────────────────────────
    # Storage content
    # ──────────────────────────────────────────

    def get_storage_content(self, node, storage) -> list:
        api = self._api()
        if not api:
            return []
        try:
            # find SR by name
            sr_refs = api.SR.get_by_name_label(storage)
            if not sr_refs:
                return []
            sr_ref = sr_refs[0]
            vdi_refs = api.SR.get_VDIs(sr_ref)
            content = []
            for vdi_ref in vdi_refs:
                rec = api.VDI.get_record(vdi_ref)
                content.append({
                    'volid': f"{storage}:{rec.get('uuid', '')}",
                    'name': rec.get('name_label', ''),
                    'size': int(rec.get('virtual_size', 0)),
                    'used': int(rec.get('physical_utilisation', 0)),
                    'format': rec.get('type', 'unknown'),
                })
            return content
        except Exception as e:
            self.logger.error(f"get_storage_content: {e}")
            return []

    # ──────────────────────────────────────────
    # Task tracking
    # ──────────────────────────────────────────

    def _track_task(self, task_ref, action, vmid) -> str:
        """Register an async XAPI task for polling."""
        task_id = str(_uuid.uuid4())[:8]
        with self._task_lock:
            self._active_tasks[task_id] = {
                'ref': task_ref,
                'action': action,
                'vmid': vmid,
                'started': datetime.now().isoformat(),
                'status': 'running',
            }
        return task_id

    def _poll_tasks(self):
        """Check status of active XAPI tasks and clean up old ones."""
        api = self._api()
        if not api:
            return

        now = time.time()
        finished = []
        expired = []
        with self._task_lock:
            for task_id, info in self._active_tasks.items():
                # NS: purge completed/failed tasks after 5 min so dict doesn't grow forever
                if info['status'] in ('completed', 'failed'):
                    try:
                        started = datetime.fromisoformat(info['started'])
                        age = now - started.timestamp()
                        if age > 300:
                            expired.append(task_id)
                    except Exception:
                        expired.append(task_id)
                    continue

                try:
                    status = api.task.get_status(info['ref'])
                    if status == 'success':
                        info['status'] = 'completed'
                        finished.append(task_id)
                        self._cached_vms = None
                        # MK May 2026 (#413) — same signature fix as site_recovery
                        broadcast_sse('xcpng_task', {'task_id': task_id,
                                       'status': 'completed', 'action': info['action']})
                    elif status in ('failure', 'cancelled'):
                        info['status'] = 'failed'
                        err_info = api.task.get_error_info(info['ref'])
                        info['error'] = str(err_info) if err_info else 'Unknown error'
                        finished.append(task_id)
                        broadcast_sse('xcpng_task', {'task_id': task_id,
                                       'status': 'failed', 'action': info['action']})
                except Exception:
                    pass  # task ref might be gone already

            for tid in expired:
                del self._active_tasks[tid]

    def get_tasks(self, limit=50) -> list:
        """Return active/recent tasks in PegaProx format."""
        with self._task_lock:
            tasks = []
            for task_id, info in list(self._active_tasks.items())[-limit:]:
                tasks.append({
                    'upid': task_id,
                    'type': info['action'],
                    'status': info['status'],
                    'vmid': info['vmid'],
                    'starttime': info['started'],
                    'node': self.current_host or '',
                    'user': 'xapi@xcpng',
                })
            return tasks

    # ──────────────────────────────────────────
    # VM action dispatch - NS Mar 2026
    # ──────────────────────────────────────────

    def vm_action(self, node, vmid, vm_type='qemu', action='start', force=False):
        """Dispatch power action - mirrors PegaProxManager interface."""
        dispatch = {
            'start': self.start_vm,
            'stop': lambda n, v: self.stop_vm(n, v) if force else self.shutdown_vm(n, v),
            'shutdown': self.shutdown_vm,
            'reboot': self.reboot_vm,
            'reset': self.reboot_vm,  # XCP-ng has no separate reset, just reboot
            'suspend': self.suspend_vm,
            'resume': self.resume_vm,
        }
        fn = dispatch.get(action)
        if not fn:
            return {'success': False, 'error': f'Unknown action: {action}'}
        try:
            task_id = fn(node, vmid)
            if task_id:
                self.logger.info(f"vm_action {action} on {vmid} -> task {task_id}")
                return {'success': True, 'data': task_id}
            return {'success': False, 'error': f'{action} returned no task'}
        except Exception as e:
            self.logger.error(f"vm_action {action} on {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # VNC / Console - MK Mar 2026
    # ──────────────────────────────────────────

    def get_vnc_ticket(self, node, vmid, vm_type='qemu'):
        """Get console connection info for XCP-ng VM.

        XAPI exposes consoles via RFB (VNC) or text console.
        We return connection details so the frontend can open a noVNC session.
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected to XCP-ng'}
        try:
            ref = self._resolve_vm(vmid)
            power = api.VM.get_power_state(ref)
            if power != 'Running':
                return {'success': False, 'error': 'VM must be running to open console'}

            console_refs = api.VM.get_consoles(ref)
            rfb_console = None
            for cref in console_refs:
                proto = api.console.get_protocol(cref)
                if proto == 'rfb':
                    rfb_console = cref
                    break

            if not rfb_console:
                return {'success': False, 'error': 'No VNC console available for this VM'}

            # console URL is like https://host/console?ref=OpaqueRef:xxxx
            location = api.console.get_location(rfb_console)
            # extract session ID for auth
            session_ref = api.xenapi._session
            return {
                'success': True,
                'type': 'xcpng_vnc',
                'url': location,
                'session_ref': session_ref,
                'host': self.host,
                'port': 443,
            }
        except ValueError as e:
            return {'success': False, 'error': str(e)}
        except Exception as e:
            self.logger.error(f"get_vnc_ticket {vmid}: {e}")
            return {'success': False, 'error': f'Console error: {e}'}

    # ──────────────────────────────────────────
    # Disk management - LW Mar 2026
    # ──────────────────────────────────────────

    def add_disk(self, node, vmid, vm_type='qemu', disk_config=None):
        """Create a new VDI and attach it to the VM via VBD."""
        if not disk_config:
            return {'success': False, 'error': 'No disk config provided'}

        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}

        try:
            ref = self._resolve_vm(vmid)

            # figure out target SR
            sr_uuid = disk_config.get('storage')
            if sr_uuid:
                sr_ref = api.SR.get_by_uuid(sr_uuid)
            else:
                # use first available shared SR, or pool default
                pool_refs = api.pool.get_all()
                sr_ref = api.pool.get_default_SR(pool_refs[0]) if pool_refs else None
                if not sr_ref or sr_ref == 'OpaqueRef:NULL':
                    return {'success': False, 'error': 'No default SR configured and no storage specified'}

            size_gb = int(str(disk_config.get('size', 32)).replace('G', '').replace('g', ''))
            size_bytes = size_gb * 1024 * 1024 * 1024

            vdi_rec = {
                'name_label': disk_config.get('name', f'disk-{vmid}'),
                'name_description': f'Added via PegaProx',
                'SR': sr_ref,
                'virtual_size': str(size_bytes),
                'type': 'user',
                'sharable': False,
                'read_only': False,
                'other_config': {},
            }
            vdi_ref = api.VDI.create(vdi_rec)

            # find next free userdevice slot
            existing_vbds = api.VM.get_VBDs(ref)
            used_devs = set()
            for vbd_ref in existing_vbds:
                try:
                    used_devs.add(api.VBD.get_userdevice(vbd_ref))
                except Exception:
                    pass
            next_dev = '1'
            for i in range(1, 16):
                if str(i) not in used_devs:
                    next_dev = str(i)
                    break

            vbd_rec = {
                'VM': ref,
                'VDI': vdi_ref,
                'userdevice': next_dev,
                'bootable': False,
                'mode': 'RW',
                'type': 'Disk',
                'empty': False,
                'other_config': {},
                'qos_algorithm_type': '',
                'qos_algorithm_params': {},
            }
            api.VBD.create(vbd_rec)

            self._cached_vms = None
            self.logger.info(f"[OK] Added {size_gb}GB disk to VM {vmid} on SR {sr_uuid or 'default'}")
            return {'success': True, 'message': f'Disk added ({size_gb}GB)'}
        except Exception as e:
            self.logger.error(f"add_disk {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def resize_vm_disk(self, node, vmid, vm_type='qemu', disk=None, size=None):
        """Resize a VDI. Only grow is supported by XAPI."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}

        try:
            ref = self._resolve_vm(vmid)
            vbds = api.VM.get_VBDs(ref)

            # disk param can be userdevice number or VDI uuid
            target_vdi = None
            for vbd_ref in vbds:
                vbd_rec = api.VBD.get_record(vbd_ref)
                if vbd_rec.get('type') != 'Disk':
                    continue
                if str(vbd_rec.get('userdevice', '')) == str(disk) or \
                   api.VDI.get_uuid(vbd_rec['VDI']) == str(disk):
                    target_vdi = vbd_rec['VDI']
                    break

            if not target_vdi:
                return {'success': False, 'error': f'Disk {disk} not found on VM {vmid}'}

            # parse size - accept "64G", "64", bytes
            new_size = str(size).replace('G', '').replace('g', '')
            try:
                sz = int(new_size)
                if sz < 4096:  # probably GB
                    sz = sz * 1024 * 1024 * 1024
            except ValueError:
                return {'success': False, 'error': f'Invalid size: {size}'}

            current = int(api.VDI.get_virtual_size(target_vdi))
            if sz <= current:
                return {'success': False, 'error': f'New size must be larger than current ({current // (1024**3)}GB). XAPI does not support shrinking.'}

            api.VDI.resize(target_vdi, str(sz))
            self.logger.info(f"Resized disk {disk} on VM {vmid} to {sz // (1024**3)}GB")
            return {'success': True, 'message': f'Disk resized to {sz // (1024**3)}GB'}
        except Exception as e:
            self.logger.error(f"resize_vm_disk {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def remove_disk(self, node, vmid, vm_type='qemu', disk_id=None, delete_data=False):
        """Detach VBD and optionally destroy the VDI."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}

        try:
            ref = self._resolve_vm(vmid)
            vbds = api.VM.get_VBDs(ref)

            target_vbd = None
            target_vdi = None
            for vbd_ref in vbds:
                vbd_rec = api.VBD.get_record(vbd_ref)
                if vbd_rec.get('type') != 'Disk':
                    continue
                dev = str(vbd_rec.get('userdevice', ''))
                vdi_uuid = api.VDI.get_uuid(vbd_rec['VDI']) if vbd_rec.get('VDI') != 'OpaqueRef:NULL' else ''
                if dev == str(disk_id) or vdi_uuid == str(disk_id):
                    target_vbd = vbd_ref
                    target_vdi = vbd_rec.get('VDI')
                    break

            if not target_vbd:
                return {'success': False, 'error': f'Disk {disk_id} not found'}

            # unplug first if VM is running
            power = api.VM.get_power_state(ref)
            if power == 'Running':
                try:
                    api.VBD.unplug(target_vbd)
                except Exception:
                    pass  # might already be unplugged

            api.VBD.destroy(target_vbd)

            if delete_data and target_vdi and target_vdi != 'OpaqueRef:NULL':
                try:
                    api.VDI.destroy(target_vdi)
                except Exception as de:
                    self.logger.warning(f"VBD removed but VDI destroy failed: {de}")

            self._cached_vms = None
            action_word = 'removed and deleted' if delete_data else 'detached'
            self.logger.info(f"Disk {disk_id} {action_word} from VM {vmid}")
            return {'success': True, 'message': f'Disk {disk_id} {action_word}'}
        except Exception as e:
            self.logger.error(f"remove_disk {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def move_disk(self, node, vmid, vm_type, disk_id, target_storage, delete_original=True):
        """Move VDI to a different SR - full implementation with VBD swap.

        NS Mar 2026 - rewritten to properly swap VBDs and clean up.
        VM must be stopped (XAPI doesn't support hot-move of individual disks).
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)

            # check power state - must be halted
            power = api.VM.get_power_state(ref)
            if power != 'Halted':
                return {'success': False,
                        'error': 'VM must be stopped for disk move. For live migration of all disks, use VM Migrate.'}

            vbds = api.VM.get_VBDs(ref)
            src_vdi = None
            src_vbd = None
            vbd_props = {}
            for vbd_ref in vbds:
                rec = api.VBD.get_record(vbd_ref)
                if rec.get('type') != 'Disk':
                    continue
                dev = str(rec.get('userdevice', ''))
                vdi_uuid = ''
                if rec.get('VDI') and rec['VDI'] != 'OpaqueRef:NULL':
                    vdi_uuid = api.VDI.get_uuid(rec['VDI'])
                if dev == str(disk_id) or vdi_uuid == str(disk_id):
                    src_vbd = vbd_ref
                    src_vdi = rec['VDI']
                    # save VBD properties for recreation
                    vbd_props = {
                        'userdevice': rec.get('userdevice', '0'),
                        'bootable': rec.get('bootable', False),
                        'mode': rec.get('mode', 'RW'),
                        'type': rec.get('type', 'Disk'),
                        'other_config': rec.get('other_config', {}),
                    }
                    break

            if not src_vdi:
                return {'success': False, 'error': f'Disk {disk_id} not found'}

            target_sr = api.SR.get_by_uuid(target_storage)

            # same-SR check
            current_sr = api.VDI.get_SR(src_vdi)
            if current_sr == target_sr:
                return {'success': False, 'error': 'Disk is already on the target storage'}

            # copy VDI to new SR (synchronous - VM is off anyway)
            old_label = api.VDI.get_name_label(src_vdi)
            new_vdi = api.VDI.copy(src_vdi, target_sr)
            api.VDI.set_name_label(new_vdi, old_label)

            # destroy old VBD
            api.VBD.destroy(src_vbd)

            # create new VBD pointing to the new VDI
            new_vbd_rec = {
                'VM': ref,
                'VDI': new_vdi,
                'userdevice': vbd_props.get('userdevice', '0'),
                'bootable': vbd_props.get('bootable', False),
                'mode': vbd_props.get('mode', 'RW'),
                'type': vbd_props.get('type', 'Disk'),
                'empty': False,
                'other_config': vbd_props.get('other_config', {}),
                'qos_algorithm_type': '',
                'qos_algorithm_params': {},
            }
            api.VBD.create(new_vbd_rec)

            # delete original VDI
            if delete_original:
                try:
                    api.VDI.destroy(src_vdi)
                except Exception as de:
                    self.logger.warning(f"move_disk: VBD swapped but old VDI cleanup failed: {de}")

            self._cached_vms = None
            self.logger.info(f"Moved disk {disk_id} of VM {vmid} to SR {target_storage}")
            return {'success': True, 'message': f'Disk {disk_id} moved successfully'}
        except Exception as e:
            self.logger.error(f"move_disk {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # CD-ROM - NS Mar 2026
    # ──────────────────────────────────────────

    def set_cdrom(self, node, vmid, iso_path=None, drive='ide2'):
        """Mount or eject ISO. iso_path should be a VDI UUID on an ISO SR."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            vbds = api.VM.get_VBDs(ref)

            # find existing CD VBD
            cd_vbd = None
            for vbd_ref in vbds:
                vbd_rec = api.VBD.get_record(vbd_ref)
                if vbd_rec.get('type') == 'CD':
                    cd_vbd = vbd_ref
                    break

            if iso_path:
                # mount - find the ISO VDI
                vdi_ref = api.VDI.get_by_uuid(iso_path)

                if cd_vbd:
                    # eject first if something is loaded
                    try:
                        if not api.VBD.get_empty(cd_vbd):
                            api.VBD.eject(cd_vbd)
                    except Exception:
                        pass
                    api.VBD.insert(cd_vbd, vdi_ref)
                else:
                    # create a new CD VBD
                    vbd_rec = {
                        'VM': ref, 'VDI': vdi_ref, 'userdevice': '3',
                        'bootable': False, 'mode': 'RO', 'type': 'CD',
                        'empty': False, 'other_config': {},
                        'qos_algorithm_type': '', 'qos_algorithm_params': {},
                    }
                    api.VBD.create(vbd_rec)
                return {'success': True, 'message': 'ISO mounted'}
            else:
                # eject
                if not cd_vbd:
                    return {'success': True, 'message': 'No CD drive found, nothing to eject'}
                try:
                    if not api.VBD.get_empty(cd_vbd):
                        api.VBD.eject(cd_vbd)
                except Exception:
                    pass
                return {'success': True, 'message': 'CD-ROM ejected'}
        except Exception as e:
            self.logger.error(f"set_cdrom {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # Network interface management - LW Mar 2026
    # ──────────────────────────────────────────

    def add_network(self, node, vmid, vm_type='qemu', net_config=None):
        """Create a VIF and attach to VM."""
        if not net_config:
            return {'success': False, 'error': 'No network config'}
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)

            # resolve network - by UUID, bridge name, or label
            net_ident = net_config.get('bridge') or net_config.get('network')
            if not net_ident:
                return {'success': False, 'error': 'bridge or network required'}

            net_ref = self._find_network(api, net_ident)
            if not net_ref:
                return {'success': False, 'error': f'Network {net_ident} not found'}

            # next free VIF device
            existing = api.VM.get_VIFs(ref)
            used = set()
            for vif in existing:
                try:
                    used.add(api.VIF.get_device(vif))
                except Exception:
                    pass
            dev = '0'
            for i in range(0, 8):
                if str(i) not in used:
                    dev = str(i)
                    break

            vif_rec = {
                'device': dev,
                'network': net_ref,
                'VM': ref,
                'MAC': net_config.get('macaddr', ''),  # empty = auto-generate
                'MTU': str(net_config.get('mtu', 1500)),
                'other_config': {},
                'qos_algorithm_type': '',
                'qos_algorithm_params': {},
            }
            vif_ref = api.VIF.create(vif_rec)

            # plug if VM running
            power = api.VM.get_power_state(ref)
            if power == 'Running':
                try:
                    api.VIF.plug(vif_ref)
                except Exception:
                    pass

            self._cached_vms = None
            return {'success': True, 'message': f'Network interface {dev} added'}
        except Exception as e:
            self.logger.error(f"add_network {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def update_network(self, node, vmid, vm_type='qemu', net_id=None, net_config=None):
        """Update VIF config. XAPI VIFs are immutable - must destroy and recreate."""
        if not net_config:
            return {'success': True, 'message': 'Nothing to update'}
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            vifs = api.VM.get_VIFs(ref)

            target_vif = None
            for vif_ref in vifs:
                if api.VIF.get_device(vif_ref) == str(net_id):
                    target_vif = vif_ref
                    break

            if not target_vif:
                return {'success': False, 'error': f'VIF device {net_id} not found'}

            old_rec = api.VIF.get_record(target_vif)
            power = api.VM.get_power_state(ref)

            # XAPI VIFs can't be modified in-place, recreate with new settings
            new_net = old_rec['network']
            if net_config.get('bridge') or net_config.get('network'):
                ident = net_config.get('bridge') or net_config['network']
                found = self._find_network(api, ident)
                if found:
                    new_net = found

            if power == 'Running':
                try:
                    api.VIF.unplug(target_vif)
                except Exception:
                    pass
            api.VIF.destroy(target_vif)

            vif_rec = {
                'device': str(net_id),
                'network': new_net,
                'VM': ref,
                'MAC': net_config.get('macaddr', old_rec.get('MAC', '')),
                'MTU': str(net_config.get('mtu', old_rec.get('MTU', '1500'))),
                'other_config': old_rec.get('other_config', {}),
                'qos_algorithm_type': old_rec.get('qos_algorithm_type', ''),
                'qos_algorithm_params': old_rec.get('qos_algorithm_params', {}),
            }
            new_vif = api.VIF.create(vif_rec)

            if power == 'Running':
                try:
                    api.VIF.plug(new_vif)
                except Exception:
                    pass

            self._cached_vms = None
            return {'success': True, 'message': f'Network {net_id} updated'}
        except Exception as e:
            self.logger.error(f"update_network {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def remove_network(self, node, vmid, vm_type='qemu', net_id=None):
        """Remove a VIF from the VM."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            vifs = api.VM.get_VIFs(ref)

            target = None
            for vif_ref in vifs:
                if api.VIF.get_device(vif_ref) == str(net_id):
                    target = vif_ref
                    break

            if not target:
                return {'success': False, 'error': f'VIF {net_id} not found'}

            power = api.VM.get_power_state(ref)
            if power == 'Running':
                try:
                    api.VIF.unplug(target)
                except Exception:
                    pass

            api.VIF.destroy(target)
            self._cached_vms = None
            return {'success': True, 'message': f'Network {net_id} removed'}
        except Exception as e:
            self.logger.error(f"remove_network {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def _find_network(self, api, ident):
        """Find network ref by UUID, bridge name, or label."""
        # try UUID first
        try:
            return api.network.get_by_uuid(ident)
        except Exception:
            pass
        # try name_label
        refs = api.network.get_by_name_label(ident)
        if refs:
            return refs[0]
        # try bridge match
        for ref in api.network.get_all():
            try:
                if api.network.get_bridge(ref) == ident:
                    return ref
            except Exception:
                pass
        return None

    # ──────────────────────────────────────────
    # Task log / cancel
    # ──────────────────────────────────────────

    def get_task_log(self, node, upid, limit=1000):
        """Return task progress info. XAPI tasks don't have detailed logs like Proxmox."""
        with self._task_lock:
            info = self._active_tasks.get(upid)
        if not info:
            return f"Task {upid} not found"
        lines = [
            f"Action: {info.get('action', '?')}",
            f"Status: {info.get('status', '?')}",
            f"VMID: {info.get('vmid', '?')}",
            f"Started: {info.get('started', '?')}",
        ]
        if info.get('error'):
            lines.append(f"Error: {info['error']}")

        # try to get progress from XAPI
        api = self._api()
        if api and info.get('ref'):
            try:
                progress = api.task.get_progress(info['ref'])
                lines.append(f"Progress: {float(progress) * 100:.0f}%")
            except Exception:
                pass
        return '\n'.join(lines)

    def stop_task(self, node, upid):
        """Cancel a running XAPI task."""
        with self._task_lock:
            info = self._active_tasks.get(upid)
        if not info:
            return False
        api = self._api()
        if not api:
            return False
        try:
            api.task.cancel(info['ref'])
            with self._task_lock:
                info['status'] = 'failed'
                info['error'] = 'Cancelled by user'
            self.logger.info(f"Task {upid} cancelled")
            return True
        except Exception as e:
            self.logger.error(f"stop_task {upid}: {e}")
            return False

    # ──────────────────────────────────────────
    # Maintenance mode - MK Mar 2026
    # ──────────────────────────────────────────

    def enter_maintenance_mode(self, node_name, skip_evacuation=False):
        """Disable host and optionally evacuate VMs.
        XCP-ng host.disable() prevents new VMs from starting.
        host.evacuate() live-migrates all running VMs away.
        Returns a MaintenanceTask so the rolling update handler works properly.
        """
        from pegaprox.models.tasks import MaintenanceTask
        api = self._api()
        if not api:
            return None

        task = MaintenanceTask(node_name)
        try:
            host_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    host_ref = href
                    break
            if not host_ref:
                self.logger.error(f"[MAINT] Host {node_name} not found")
                task.status = 'failed'
                task.error = f'Host {node_name} not found'
                return None

            api.host.disable(host_ref)
            self.logger.info(f"[MAINT] Host {node_name} disabled")

            if not skip_evacuation:
                try:
                    api.host.evacuate(host_ref)
                    self.logger.info(f"[MAINT] Host {node_name} evacuated")
                except Exception as ev:
                    self.logger.warning(f"[MAINT] Evacuation of {node_name} failed: {ev}")
                    task.status = 'completed_with_errors'
                    task.error = str(ev)

            if task.status not in ('failed', 'completed_with_errors'):
                task.status = 'completed'

            self._cached_nodes = None
            # NS: store in nodes_in_maintenance so rolling update wait loop sees it
            with self.maintenance_lock:
                self.nodes_in_maintenance[node_name] = task
            return task
        except Exception as e:
            self.logger.error(f"enter_maintenance {node_name}: {e}")
            task.status = 'failed'
            task.error = str(e)
            return None

    def exit_maintenance_mode(self, node_name):
        """Re-enable a host that was in maintenance."""
        api = self._api()
        if not api:
            return None
        try:
            host_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    host_ref = href
                    break
            if not host_ref:
                self.logger.error(f"[MAINT] Host {node_name} not found")
                return None
            api.host.enable(host_ref)
            self._cached_nodes = None
            with self.maintenance_lock:
                self.nodes_in_maintenance.pop(node_name, None)
            self.logger.info(f"[MAINT] Host {node_name} re-enabled")
            return {'status': 'completed', 'node': node_name}
        except Exception as e:
            self.logger.error(f"exit_maintenance {node_name}: {e}")
            return None

    def get_maintenance_status(self, node_name=None):
        """Check which hosts are disabled (in maintenance).
        node_name param for API compat - if given, return status for that node only.
        """
        api = self._api()
        if not api:
            return {}
        result = {}
        try:
            for href in api.host.get_all():
                hostname = api.host.get_hostname(href)
                enabled = api.host.get_enabled(href)
                if not enabled:
                    result[hostname] = {'status': 'maintenance', 'node': hostname}
        except Exception:
            pass
        if node_name:
            return result.get(node_name, {})
        return result

    # ──────────────────────────────────────────
    # Node details - NS Mar 2026
    # ──────────────────────────────────────────

    def get_node_details(self, node_name):
        """Get detailed host info - hardware, software, etc."""
        api = self._api()
        if not api:
            return {}
        try:
            host_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    host_ref = href
                    break
            if not host_ref:
                return {}

            rec = api.host.get_record(host_ref)
            sw = rec.get('software_version', {})
            cpu_info = rec.get('cpu_info', {})
            bios = rec.get('bios_strings', {})

            metrics_ref = rec.get('metrics', 'OpaqueRef:NULL')
            mem_total = mem_free = 0
            if metrics_ref != 'OpaqueRef:NULL':
                try:
                    m = api.host_metrics.get_record(metrics_ref)
                    mem_total = int(m.get('memory_total', 0))
                    mem_free = int(m.get('memory_free', 0))
                except Exception:
                    pass

            # PCIs
            pci_list = []
            for pci_ref in rec.get('PCIs', []):
                try:
                    prec = api.PCI.get_record(pci_ref)
                    pci_list.append({
                        'id': prec.get('pci_id', ''),
                        'class': prec.get('class_name', ''),
                        'vendor': prec.get('vendor_name', ''),
                        'device': prec.get('device_name', ''),
                    })
                except Exception:
                    pass

            return {
                'hostname': rec.get('hostname', ''),
                'uuid': rec.get('uuid', ''),
                'address': rec.get('address', ''),
                'enabled': rec.get('enabled', True),
                'cpu_model': cpu_info.get('modelname', ''),
                'cpu_count': int(cpu_info.get('cpu_count', 0)),
                'cpu_socket_count': int(cpu_info.get('socket_count', 0)),
                'memory_total': mem_total,
                'memory_free': mem_free,
                'xen_version': sw.get('xen', ''),
                'product_version': sw.get('product_version', ''),
                'product_brand': sw.get('product_brand', 'XCP-ng'),
                'kernel_version': sw.get('linux', ''),
                'build_number': sw.get('build_number', ''),
                'bios_vendor': bios.get('bios-vendor', ''),
                'system_manufacturer': bios.get('system-manufacturer', ''),
                'system_product': bios.get('system-product-name', ''),
                'pci_devices': pci_list[:50],  # cap it
            }
        except Exception as e:
            self.logger.error(f"get_node_details {node_name}: {e}")
            return {}

    # ──────────────────────────────────────────
    # Storage upload (ISO) - NS Mar 2026
    # ──────────────────────────────────────────

    def upload_to_storage(self, node, storage, filename, file_stream, content_type='iso'):
        """Upload an ISO or template to an ISO SR via XAPI HTTP import.
        Uses the /import_raw_vdi endpoint with VDI.create for ISO SRs.
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            # find the ISO SR
            sr_refs = api.SR.get_by_name_label(storage)
            if not sr_refs:
                # try UUID
                try:
                    sr_ref = api.SR.get_by_uuid(storage)
                    sr_refs = [sr_ref]
                except Exception:
                    return {'success': False, 'error': f'Storage {storage} not found'}
            sr_ref = sr_refs[0]
            sr_type = api.SR.get_type(sr_ref)

            # for ISO SRs, we use HTTP PUT to the host
            import requests as _req
            session_ref = api.xenapi._session
            host_url = f"https://{self.host}"

            if sr_type == 'iso' or content_type == 'iso':
                # XAPI ISO import is via VDI create + HTTP upload
                vdi_rec = {
                    'name_label': _sanitize_str(filename),
                    'name_description': 'Uploaded via PegaProx',
                    'SR': sr_ref,
                    'virtual_size': '0',  # will be set by import
                    'type': 'user',
                    'sharable': False,
                    'read_only': True,
                    'other_config': {},
                }
                vdi_ref = api.VDI.create(vdi_rec)
                vdi_uuid = api.VDI.get_uuid(vdi_ref)

                # HTTP PUT to import endpoint — URL built via defensive helper
                url = _build_xapi_import_vdi_url(host_url, session_ref, vdi_uuid, "raw")
                _ssl_verify = getattr(self.config, 'ssl_verification', False)
                resp = _req.put(url, data=file_stream, verify=_ssl_verify,
                               headers={'Content-Type': 'application/octet-stream'})
                if resp.status_code in (200, 204):
                    self.logger.info(f"Uploaded {filename} to {storage}")
                    return {'success': True, 'message': f'{filename} uploaded'}
                else:
                    # rollback
                    try:
                        api.VDI.destroy(vdi_ref)
                    except Exception:
                        pass
                    return {'success': False, 'error': f'Upload failed: HTTP {resp.status_code}'}
            else:
                return {'success': False, 'error': 'Only ISO upload supported for XCP-ng'}
        except Exception as e:
            self.logger.error(f"upload_to_storage: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # RRD metrics - NS Mar 2026
    # XCP-ng exposes per-host and per-VM RRD via HTTP
    # ──────────────────────────────────────────

    def _rrd_fetch(self, path, params=None):
        """Fetch RRD XML from XCP-ng host and parse into rows."""
        # NS May 2026 — defusedxml: RRD payload is bytes off the wire from the
        # remote host. Even if we trust the cluster, an attacker who lands on
        # the network path could inject XXE/entity-expansion payloads. cheap fix.
        from defusedxml import ElementTree as ET
        import requests as _req

        host_url = f"https://{self.host}"
        with self._session_lock:
            if not self._session:
                return None, None
            sid = self._session._session

        p = {'session_id': sid}
        if params:
            p.update(params)

        try:
            url = _build_xapi_rrd_url(host_url, path)
            _ssl_verify = getattr(self.config, 'ssl_verification', False)
            resp = _req.get(url, params=p, verify=_ssl_verify, timeout=15)
            if resp.status_code != 200:
                return None, None
            root = ET.fromstring(resp.text)
        except Exception as e:
            self.logger.error(f"_rrd_fetch {path}: {e}")
            return None, None

        meta = root.find('meta')
        if meta is None:
            return None, None

        legends = []
        leg_el = meta.find('legend')
        if leg_el is not None:
            legends = [e.text or '' for e in leg_el.findall('entry')]

        rows = []
        data_el = root.find('data')
        if data_el is not None:
            for row in data_el.findall('row'):
                t_el = row.find('t')
                vals = row.findall('v')
                if t_el is None:
                    continue
                ts = int(t_el.text)
                values = []
                for v in vals:
                    try:
                        values.append(float(v.text) if v.text and v.text != 'NaN' else 0.0)
                    except (ValueError, TypeError):
                        values.append(0.0)
                rows.append((ts, values))

        return legends, rows

    def get_vm_rrd(self, node, vmid, vm_type='qemu', timeframe='hour'):
        """Get VM metrics - matches PegaProxManager output shape."""
        db = get_db()
        vm_uuid = db.xcpng_resolve_vmid(self.id, vmid)
        if not vm_uuid:
            return {'success': False, 'error': f'VM {vmid} not found'}

        tf_seconds = {'hour': 3600, 'day': 86400, 'week': 604800,
                      'month': 2592000, 'year': 31536000}
        start = int(time.time()) - tf_seconds.get(timeframe, 3600)

        legends, rows = self._rrd_fetch('rrd_updates', {
            'start': start, 'cf': 'AVERAGE', 'host': 'false'
        })
        if legends is None:
            return {'success': False, 'error': 'Could not fetch RRD data'}

        # filter legend entries for this VM uuid
        vm_prefix = f"AVERAGE:vm:{vm_uuid}:"
        col_map = {}
        for i, leg in enumerate(legends):
            if leg.startswith(vm_prefix):
                metric = leg[len(vm_prefix):]
                col_map[metric] = i

        formatted = {
            'timeframe': timeframe, 'vmid': vmid, 'node': node,
            'type': vm_type,
            'metrics': {
                'cpu': [], 'memory': [],
                'disk_read': [], 'disk_write': [],
                'net_in': [], 'net_out': []
            },
            'timestamps': []
        }

        # aggregate multi-vif / multi-vbd columns
        cpu_cols = [i for m, i in col_map.items() if m.startswith('cpu')]
        netin_cols = [i for m, i in col_map.items() if m.startswith('vif_') and m.endswith('_rx')]
        netout_cols = [i for m, i in col_map.items() if m.startswith('vif_') and m.endswith('_tx')]
        dkr_cols = [i for m, i in col_map.items() if m.startswith('vbd_') and m.endswith('_read')]
        dkw_cols = [i for m, i in col_map.items() if m.startswith('vbd_') and m.endswith('_write')]
        mem_col = col_map.get('memory', None)
        mem_target = col_map.get('memory_target', None)
        mem_free_col = col_map.get('memory_internal_free', None)

        for ts, vals in rows:
            formatted['timestamps'].append(ts)
            # cpu: XCP-ng gives fraction per vcpu
            cpu_val = sum(vals[c] for c in cpu_cols) / max(len(cpu_cols), 1) if cpu_cols else 0
            formatted['metrics']['cpu'].append(round(cpu_val * 100, 2))

            # memory percent
            if mem_col is not None and mem_target is not None:
                used = vals[mem_col]
                target = vals[mem_target] if vals[mem_target] > 0 else 1
                formatted['metrics']['memory'].append(round(used / target * 100, 2))
            elif mem_free_col is not None and mem_col is not None:
                total_kib = vals[mem_col] / 1024 if vals[mem_col] > 1024 else vals[mem_col]
                free_kib = vals[mem_free_col]
                pct = ((total_kib - free_kib) / total_kib * 100) if total_kib > 0 else 0
                formatted['metrics']['memory'].append(round(max(0, min(100, pct)), 2))
            else:
                formatted['metrics']['memory'].append(0)

            formatted['metrics']['net_in'].append(sum(vals[c] for c in netin_cols))
            formatted['metrics']['net_out'].append(sum(vals[c] for c in netout_cols))
            formatted['metrics']['disk_read'].append(sum(vals[c] for c in dkr_cols))
            formatted['metrics']['disk_write'].append(sum(vals[c] for c in dkw_cols))

        return {'success': True, 'data': formatted}

    def get_node_rrddata(self, node: str, timeframe: str = 'hour'):
        """Get node metrics - same output shape as PegaProxManager."""
        tf_seconds = {'hour': 3600, 'day': 86400, 'week': 604800,
                      'month': 2592000, 'year': 31536000}
        start = int(time.time()) - tf_seconds.get(timeframe, 3600)

        # resolve node -> host UUID
        api = self._api()
        host_uuid = None
        if api:
            try:
                for href in api.host.get_all():
                    hn = api.host.get_hostname(href)
                    if hn == node or api.host.get_name_label(href) == node:
                        host_uuid = api.host.get_uuid(href)
                        break
            except Exception:
                pass

        legends, rows = self._rrd_fetch('rrd_updates', {
            'start': start, 'cf': 'AVERAGE', 'host': 'true'
        })
        if legends is None:
            return {'success': False, 'error': 'Could not fetch RRD data'}

        host_prefix = f"AVERAGE:host:{host_uuid}:" if host_uuid else "AVERAGE:host:"
        col_map = {}
        for i, leg in enumerate(legends):
            if host_uuid:
                if leg.startswith(host_prefix):
                    col_map[leg[len(host_prefix):]] = i
            elif ':host:' in leg:
                parts = leg.split(':')
                if len(parts) >= 4:
                    col_map[parts[3]] = i

        formatted = {
            'timeframe': timeframe, 'node': node,
            'metrics': {
                'cpu': [], 'memory': [], 'swap': [],
                'iowait': [], 'loadavg': [],
                'net_in': [], 'net_out': [], 'rootfs': []
            },
            'timestamps': []
        }

        cpu_cols = [i for m, i in col_map.items() if m.startswith('cpu') and not m.startswith('cpu_avg')]
        cpu_avg_col = col_map.get('cpu_avg', None)
        mem_total_col = col_map.get('memory_total_kib', None)
        mem_free_col = col_map.get('memory_free_kib', None)
        loadavg_col = col_map.get('loadavg', None)
        netin_cols = [i for m, i in col_map.items() if m.startswith('pif_') and m.endswith('_rx')]
        netout_cols = [i for m, i in col_map.items() if m.startswith('pif_') and m.endswith('_tx')]

        for ts, vals in rows:
            formatted['timestamps'].append(ts)

            if cpu_avg_col is not None:
                formatted['metrics']['cpu'].append(round(vals[cpu_avg_col] * 100, 2))
            elif cpu_cols:
                avg = sum(vals[c] for c in cpu_cols) / len(cpu_cols)
                formatted['metrics']['cpu'].append(round(avg * 100, 2))
            else:
                formatted['metrics']['cpu'].append(0)

            if mem_total_col is not None and mem_free_col is not None:
                total = vals[mem_total_col]
                free = vals[mem_free_col]
                pct = ((total - free) / total * 100) if total > 0 else 0
                formatted['metrics']['memory'].append(round(pct, 2))
            else:
                formatted['metrics']['memory'].append(0)

            # XCP-ng dom0 doesn't expose swap/iowait the same way
            formatted['metrics']['swap'].append(0)
            formatted['metrics']['iowait'].append(0)
            formatted['metrics']['loadavg'].append(round(vals[loadavg_col], 2) if loadavg_col is not None else 0)
            formatted['metrics']['rootfs'].append(0)

            formatted['metrics']['net_in'].append(sum(vals[c] for c in netin_cols))
            formatted['metrics']['net_out'].append(sum(vals[c] for c in netout_cols))

        return {'success': True, 'data': formatted}

    # ──────────────────────────────────────────
    # Guest metrics (IP, OS, PV driver status)
    # ──────────────────────────────────────────

    def get_guest_metrics(self, node, vmid, vm_type='qemu'):
        """Get guest agent info for a VM - IP, OS, PV drivers."""
        api = self._api()
        if not api:
            return {}
        try:
            ref = self._resolve_vm(vmid)
            gm_ref = api.VM.get_guest_metrics(ref)
            if gm_ref == 'OpaqueRef:NULL':
                return {'pv_drivers_detected': False, 'networks': {}, 'os_version': {}}

            rec = api.VM_guest_metrics.get_record(gm_ref)
            networks = rec.get('networks', {})
            os_ver = rec.get('os_version', {})
            pv_version = rec.get('PV_drivers_version', {})
            memory = rec.get('memory', {})

            # flatten network map: {'0/ip': '10.0.0.1', '0/ipv6/0': '...'} -> list
            ips = []
            seen = set()
            for k, v in networks.items():
                if '/ip' in k and v not in seen:
                    seen.add(v)
                    ips.append(v)

            return {
                'pv_drivers_detected': bool(pv_version),
                'pv_drivers_version': pv_version.get('major', '') + '.' + pv_version.get('minor', '') if pv_version else '',
                'pv_drivers_up_to_date': rec.get('PV_drivers_up_to_date', False),
                'ip_addresses': ips,
                'networks': networks,
                'os_version': os_ver,
                'os_name': os_ver.get('name', ''),
                'memory': memory,
                'live': rec.get('live', False),
            }
        except Exception as e:
            self.logger.error(f"get_guest_metrics {vmid}: {e}")
            return {}

    # ──────────────────────────────────────────
    # Pool HA - MK Mar 2026
    # ──────────────────────────────────────────

    def get_ha_status(self) -> Dict:
        """Get pool HA status including per-VM restart priorities."""
        api = self._api()
        if not api:
            return {'enabled': False, 'error': 'Not connected'}
        try:
            pool_refs = api.pool.get_all()
            if not pool_refs:
                return {'enabled': False}
            pool = api.pool.get_record(pool_refs[0])

            ha_enabled = pool.get('ha_enabled', False)
            result = {
                'enabled': ha_enabled,
                'allow_overcommit': pool.get('ha_allow_overcommit', False),
                'overcommitted': pool.get('ha_overcommitted', False),
                'host_failures_to_tolerate': int(pool.get('ha_host_failures_to_tolerate', 0)),
                'plan_exists_for': int(pool.get('ha_plan_exists_for', 0)),
                'ha_statefiles': pool.get('ha_statefiles', []),
            }

            if ha_enabled:
                vm_ha = []
                for vm_ref in api.VM.get_all():
                    try:
                        if api.VM.get_is_a_template(vm_ref):
                            continue
                        if api.VM.get_is_control_domain(vm_ref):
                            continue
                        prio = api.VM.get_ha_restart_priority(vm_ref)
                        if prio:
                            name = api.VM.get_name_label(vm_ref)
                            uuid = api.VM.get_uuid(vm_ref)
                            db = get_db()
                            vmid = db.xcpng_get_vmid(self.id, uuid)
                            vm_ha.append({
                                'vmid': vmid,
                                'name': name,
                                'uuid': uuid,
                                'restart_priority': prio,
                                'order': int(api.VM.get_order(vm_ref) or 0),
                                'start_delay': int(api.VM.get_start_delay(vm_ref) or 0),
                            })
                    except Exception:
                        continue
                result['protected_vms'] = vm_ha

            return result
        except Exception as e:
            self.logger.error(f"get_ha_status: {e}")
            return {'enabled': False, 'error': str(e)}

    def set_vm_ha_restart_priority(self, vmid, priority: str):
        """Set HA restart priority for a VM.
        priority: 'restart', 'best-effort', '' (disabled)
        """
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            api.VM.set_ha_restart_priority(ref, priority)
            self.logger.info(f"Set HA priority for VM {vmid} to '{priority}'")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"set_vm_ha_restart_priority {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    def enable_pool_ha(self, heartbeat_srs=None, host_failures_to_tolerate=1):
        """Enable HA on the pool. heartbeat_srs: list of SR refs for state files."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            sr_refs = []
            if heartbeat_srs:
                for sr_id in heartbeat_srs:
                    try:
                        sr_refs.append(api.SR.get_by_uuid(sr_id))
                    except Exception:
                        found = api.SR.get_by_name_label(sr_id)
                        if found:
                            sr_refs.append(found[0])

            config = {'timeout': '30'}
            api.pool.enable_ha(sr_refs, config)
            pool_refs = api.pool.get_all()
            if pool_refs:
                api.pool.set_ha_host_failures_to_tolerate(pool_refs[0], host_failures_to_tolerate)
            self.logger.info(f"Pool HA enabled (tolerance={host_failures_to_tolerate})")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"enable_pool_ha: {e}")
            return {'success': False, 'error': str(e)}

    def disable_pool_ha(self):
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            api.pool.disable_ha()
            self.logger.info("Pool HA disabled")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"disable_pool_ha: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # PIF / physical network interfaces
    # LW: per-node physical NIC info, bonds, VLANs
    # ──────────────────────────────────────────

    def get_host_pifs(self, node_name) -> list:
        """Get physical interfaces for a host."""
        api = self._api()
        if not api:
            return []
        try:
            host_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    host_ref = href
                    break
            if not host_ref:
                return []

            pifs = []
            for pif_ref in api.PIF.get_all():
                rec = api.PIF.get_record(pif_ref)
                if rec.get('host') != host_ref:
                    continue
                pifs.append({
                    'uuid': rec.get('uuid', ''),
                    'device': rec.get('device', ''),
                    'MAC': rec.get('MAC', ''),
                    'MTU': int(rec.get('MTU', 1500)),
                    'VLAN': int(rec.get('VLAN', -1)),
                    'ip': rec.get('IP', ''),
                    'netmask': rec.get('netmask', ''),
                    'gateway': rec.get('gateway', ''),
                    'DNS': rec.get('DNS', ''),
                    'ip_configuration_mode': rec.get('ip_configuration_mode', ''),
                    'ipv6': rec.get('IPv6', []),
                    'currently_attached': rec.get('currently_attached', False),
                    'physical': rec.get('physical', False),
                    'management': rec.get('management', False),
                    'bond_slave_of': rec.get('bond_slave_of', 'OpaqueRef:NULL') != 'OpaqueRef:NULL',
                    'speed': int(rec.get('speed', 0)),
                    'duplex': rec.get('duplex', 'unknown'),
                    'carrier': rec.get('carrier', False),
                    'vendor_name': rec.get('vendor_name', ''),
                    'device_name': rec.get('device_name', ''),
                })
            return sorted(pifs, key=lambda p: p['device'])
        except Exception as e:
            self.logger.error(f"get_host_pifs {node_name}: {e}")
            return []

    def get_bonds(self, node_name) -> list:
        """Get bond interfaces for a host."""
        api = self._api()
        if not api:
            return []
        try:
            host_ref = None
            for href in api.host.get_all():
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    host_ref = href
                    break
            if not host_ref:
                return []

            bonds = []
            for bond_ref in api.Bond.get_all():
                rec = api.Bond.get_record(bond_ref)
                master_ref = rec.get('master', 'OpaqueRef:NULL')
                if master_ref == 'OpaqueRef:NULL':
                    continue
                try:
                    master_host = api.PIF.get_host(master_ref)
                    if master_host != host_ref:
                        continue
                except Exception:
                    continue

                slaves = []
                for s_ref in rec.get('slaves', []):
                    try:
                        slaves.append(api.PIF.get_device(s_ref))
                    except Exception:
                        pass

                bonds.append({
                    'uuid': rec.get('uuid', ''),
                    'master': api.PIF.get_device(master_ref),
                    'mode': rec.get('mode', 'balance-slb'),
                    'slaves': slaves,
                    'primary_slave': rec.get('primary_slave', ''),
                })
            return bonds
        except Exception as e:
            self.logger.error(f"get_bonds {node_name}: {e}")
            return []

    # ──────────────────────────────────────────
    # VM guest agent - enrich VM list with IPs
    # ──────────────────────────────────────────

    def get_vm_addresses(self, vmid) -> list:
        """Return list of IP addresses from guest agent."""
        gm = self.get_guest_metrics(None, vmid)
        return gm.get('ip_addresses', [])

    # ──────────────────────────────────────────
    # SSH infrastructure - NS Mar 2026
    # needed for node config, updates, hardening
    # ──────────────────────────────────────────

    def _get_host_ip(self, node_name):
        """Resolve hostname to IP via XAPI host.get_address()."""
        api = self._api()
        if not api:
            return self.config.host
        try:
            for href in api.host.get_all():
                hn = api.host.get_hostname(href)
                if hn == node_name or api.host.get_name_label(href) == node_name:
                    return api.host.get_address(href)
        except Exception:
            pass
        return self.config.host

    def get_node_ip(self, node_name):
        """Public wrapper - used by API layer for shell connections."""
        return self._get_host_ip(node_name)

    def _ssh_connect(self, host, retries=3):
        """Open SSH connection to XCP-ng host."""
        import paramiko

        ssh_user = self.config.ssh_user or 'root'
        ssh_port = getattr(self.config, 'ssh_port', 22) or 22

        for attempt in range(retries):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # try key auth first
                ssh_key = getattr(self.config, 'ssh_key', '')
                if ssh_key and os.path.isfile(ssh_key):
                    client.connect(host, port=ssh_port, username=ssh_user,
                                   key_filename=ssh_key, timeout=15, allow_agent=False)
                else:
                    # password from cluster config
                    client.connect(host, port=ssh_port, username=ssh_user,
                                   password=self.config.pass_, timeout=15,
                                   allow_agent=False, look_for_keys=False)
                return client
            except Exception as e:
                if attempt == retries - 1:
                    self.logger.error(f"SSH to {host} failed: {e}")
                time.sleep(3)
        return None

    def _ssh_exec(self, node_name, cmd, timeout=60):
        """Run command on XCP-ng host via SSH. Returns (exit_code, stdout, stderr)."""
        host_ip = self._get_host_ip(node_name)
        ssh = self._ssh_connect(host_ip)
        if not ssh:
            return -1, '', 'SSH connection failed'
        try:
            _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            return rc, out, err
        except Exception as e:
            return -1, '', str(e)
        finally:
            try:
                ssh.close()
            except Exception:
                pass

    # ──────────────────────────────────────────
    # Node config (DNS, time, hosts) - via SSH
    # MK Mar 2026 - same interface as Proxmox but SSH-based
    # ──────────────────────────────────────────

    def get_node_dns(self, node):
        """Read DNS config from /etc/resolv.conf."""
        rc, out, _ = self._ssh_exec(node, "cat /etc/resolv.conf 2>/dev/null")
        if rc != 0:
            return {}
        dns_servers = []
        search_domain = ''
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('nameserver '):
                dns_servers.append(line.split(None, 1)[1])
            elif line.startswith('search '):
                search_domain = line.split(None, 1)[1]
        result = {'search': search_domain}
        for i, srv in enumerate(dns_servers[:3], 1):
            result[f'dns{i}'] = srv
        return result

    def update_node_dns(self, node, dns_config):
        # MK: validate input to prevent shell injection
        _dns_re = re.compile(r'^[a-zA-Z0-9\.\-:]+$')
        search = dns_config.get('search', '').strip()
        if search and not re.match(r'^[a-zA-Z0-9\.\- ]+$', search):
            return {'success': False, 'error': 'Invalid search domain'}
        lines = []
        if search:
            lines.append(f"search {search}")
        for key in ['dns1', 'dns2', 'dns3']:
            val = dns_config.get(key, '').strip()
            if val:
                if not _dns_re.match(val):
                    return {'success': False, 'error': f'Invalid DNS server: {val}'}
                lines.append(f"nameserver {val}")
        if not lines:
            return {'success': False, 'error': 'No DNS servers specified'}

        content = '\n'.join(lines) + '\n'
        # Use random delimiter to prevent heredoc terminator injection
        delimiter = f"EOF_{_uuid.uuid4().hex}"
        rc, _, err = self._ssh_exec(node,
            f"cat > /etc/resolv.conf << '{delimiter}'\n{content}{delimiter}")
        if rc == 0:
            return {'success': True, 'message': 'DNS updated'}
        return {'success': False, 'error': err or 'Failed to write resolv.conf'}

    def get_node_hosts(self, node):
        """Return /etc/hosts content."""
        rc, out, _ = self._ssh_exec(node, "cat /etc/hosts 2>/dev/null")
        return out if rc == 0 else ''

    def update_node_hosts(self, node, hosts_content):
        if not hosts_content:
            return {'success': False, 'error': 'Empty hosts content'}
        # Use random delimiter to prevent heredoc terminator injection
        delimiter = f"EOF_{_uuid.uuid4().hex}"
        rc, _, err = self._ssh_exec(node,
            f"cat > /etc/hosts << '{delimiter}'\n{hosts_content}\n{delimiter}")
        if rc == 0:
            return {'success': True, 'message': 'Hosts updated'}
        return {'success': False, 'error': err or 'Failed to write hosts file'}

    def get_node_time(self, node):
        """Get timezone and current time from node."""
        rc, out, _ = self._ssh_exec(node,
            "timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null; echo '---'; date -Iseconds")
        if rc != 0:
            return {'timezone': 'UTC'}
        parts = out.split('---')
        tz = parts[0].strip().splitlines()[-1] if parts else 'UTC'
        localtime = parts[1].strip() if len(parts) > 1 else ''
        return {'timezone': tz, 'localtime': localtime}

    def update_node_time(self, node, timezone):
        # validate timezone - only allow safe chars (e.g. "Europe/Berlin", "US/Eastern")
        if not re.match(r'^[a-zA-Z0-9_/\-\+]+$', timezone):
            return {'success': False, 'error': f'Invalid timezone: {timezone}'}
        # timedatectl is available on XCP-ng 8.x
        rc, _, err = self._ssh_exec(node, f"timedatectl set-timezone '{timezone}' 2>&1")
        if rc == 0:
            return {'success': True, 'message': 'Timezone updated'}
        # fallback: symlink (validate path exists)
        rc2, _, err2 = self._ssh_exec(node,
            f"test -f /usr/share/zoneinfo/{timezone} && ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime && echo '{timezone}' > /etc/timezone")
        if rc2 == 0:
            return {'success': True, 'message': 'Timezone updated (fallback)'}
        return {'success': False, 'error': err or err2 or 'timedatectl failed'}

    # ──────────────────────────────────────────
    # Node network config - via XAPI
    # LW Mar 2026 - XAPI changes are immediate, no apply/revert
    # ──────────────────────────────────────────

    def _resolve_host_ref(self, node_name):
        """Find XAPI host ref by hostname or name_label."""
        api = self._api()
        if not api:
            return None, None
        for href in api.host.get_all():
            try:
                if api.host.get_hostname(href) == node_name or \
                   api.host.get_name_label(href) == node_name:
                    return api, href
            except Exception:
                pass
        return api, None

    def get_node_network_config(self, node):
        """Return list of network interfaces with IP config - same shape as Proxmox."""
        api = self._api()
        if not api:
            return []
        try:
            interfaces = []
            for pif_ref in api.PIF.get_all():
                rec = api.PIF.get_record(pif_ref)
                host_ref = rec.get('host', 'OpaqueRef:NULL')
                # filter by node
                try:
                    hn = api.host.get_hostname(host_ref)
                except Exception:
                    continue
                if hn != node and api.host.get_name_label(host_ref) != node:
                    continue

                net_ref = rec.get('network', 'OpaqueRef:NULL')
                bridge = ''
                net_name = ''
                if net_ref != 'OpaqueRef:NULL':
                    try:
                        bridge = api.network.get_bridge(net_ref)
                        net_name = api.network.get_name_label(net_ref)
                    except Exception:
                        pass

                vlan_tag = int(rec.get('VLAN', -1))
                iface_type = 'eth'
                if vlan_tag >= 0:
                    iface_type = 'vlan'
                elif rec.get('bond_slave_of', 'OpaqueRef:NULL') != 'OpaqueRef:NULL':
                    iface_type = 'bond_slave'
                elif bridge:
                    iface_type = 'bridge'

                interfaces.append({
                    'iface': rec.get('device', ''),
                    'type': iface_type,
                    'active': rec.get('currently_attached', False),
                    'address': rec.get('IP', ''),
                    'netmask': rec.get('netmask', ''),
                    'gateway': rec.get('gateway', ''),
                    'cidr': f"{rec.get('IP', '')}/{rec.get('netmask', '')}" if rec.get('IP') else '',
                    'bridge': bridge,
                    'network': net_name,
                    'method': rec.get('ip_configuration_mode', 'None').lower(),
                    'families': ['inet'] if rec.get('IP') else [],
                    'autostart': rec.get('currently_attached', False),
                    'mac': rec.get('MAC', ''),
                    'mtu': int(rec.get('MTU', 1500)),
                    'vlan-id': vlan_tag if vlan_tag >= 0 else None,
                    'comments': '',
                    'uuid': rec.get('uuid', ''),
                })
            return sorted(interfaces, key=lambda x: x['iface'])
        except Exception as e:
            self.logger.error(f"get_node_network_config {node}: {e}")
            return []

    def create_node_network(self, node, iface, iface_type, config):
        """Create a new network (bridge) or VLAN on XCP-ng."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            if iface_type == 'vlan':
                # need the PIF device and VLAN tag
                vlan_tag = config.get('vlan-id') or config.get('vlan_id')
                pif_device = config.get('bridge_ports') or config.get('device', iface)
                if not vlan_tag:
                    return {'success': False, 'error': 'VLAN tag required'}
                # find PIF ref
                pif_ref = None
                for pr in api.PIF.get_all():
                    if api.PIF.get_device(pr) == pif_device:
                        h = api.PIF.get_host(pr)
                        if api.host.get_hostname(h) == node:
                            pif_ref = pr
                            break
                if not pif_ref:
                    return {'success': False, 'error': f'PIF {pif_device} not found on {node}'}
                net_ref = api.network.create({
                    'name_label': iface,
                    'name_description': config.get('comments', f'VLAN {vlan_tag}'),
                    'other_config': {},
                })
                api.VLAN.create(pif_ref, str(vlan_tag), net_ref)
            else:
                # create a bridge/internal network
                net_ref = api.network.create({
                    'name_label': iface,
                    'name_description': config.get('comments', ''),
                    'other_config': {},
                })
                # NS: if IP config provided, need to assign via PIF
                # but new internal networks don't have a PIF automatically

            self._cached_nodes = None
            self.logger.info(f"Created network {iface} ({iface_type}) on {node}")
            return {'success': True, 'message': f'Interface {iface} created'}
        except Exception as e:
            self.logger.error(f"create_node_network: {e}")
            return {'success': False, 'error': str(e)}

    def update_node_network(self, node, iface, config):
        """Update PIF IP config via XAPI reconfigure_ip."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            # find PIF for this device on node
            target_pif = None
            for pr in api.PIF.get_all():
                rec = api.PIF.get_record(pr)
                if rec.get('device') != iface:
                    continue
                h = rec.get('host', 'OpaqueRef:NULL')
                try:
                    if api.host.get_hostname(h) == node or api.host.get_name_label(h) == node:
                        target_pif = pr
                        break
                except Exception:
                    pass
            if not target_pif:
                return {'success': False, 'error': f'Interface {iface} not found on {node}'}

            mode = config.get('method', config.get('ip_configuration_mode', 'DHCP')).upper()
            if mode not in ('DHCP', 'STATIC', 'NONE'):
                mode = 'DHCP'

            if mode == 'STATIC':
                ip = config.get('address', '')
                mask = config.get('netmask', '255.255.255.0')
                gw = config.get('gateway', '')
                dns = config.get('dns', '')
                api.PIF.reconfigure_ip(target_pif, 'Static', ip, mask, gw, dns)
            elif mode == 'DHCP':
                api.PIF.reconfigure_ip(target_pif, 'DHCP', '', '', '', '')
            else:
                api.PIF.reconfigure_ip(target_pif, 'None', '', '', '', '')

            self._cached_nodes = None
            return {'success': True, 'message': 'Network updated'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def delete_node_network(self, node, iface):
        """Delete a network. Only user-created networks can be removed."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            # find by name_label
            nets = api.network.get_by_name_label(iface)
            if not nets:
                return {'success': False, 'error': f'Network {iface} not found'}
            # check no VIFs attached
            vifs = api.network.get_VIFs(nets[0])
            if vifs:
                return {'success': False, 'error': f'Network {iface} has {len(vifs)} VIF(s) attached, remove them first'}
            # check not management network
            pifs = api.network.get_PIFs(nets[0])
            for pr in pifs:
                if api.PIF.get_management(pr):
                    return {'success': False, 'error': 'Cannot delete management network'}
            # destroy associated VLANs
            for pr in pifs:
                vlan_ref = api.PIF.get_VLAN_master_of(pr)
                if vlan_ref != 'OpaqueRef:NULL':
                    api.VLAN.destroy(vlan_ref)
            api.network.destroy(nets[0])
            self.logger.info(f"Deleted network {iface}")
            return {'success': True, 'message': f'Interface {iface} deleted'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def apply_node_network(self, node):
        """No-op - XAPI network changes are immediate."""
        return {'success': True, 'message': 'Network changes applied (XCP-ng applies immediately)'}

    def revert_node_network(self, node):
        """No-op - XAPI doesn't have pending network changes."""
        return {'success': True, 'message': 'Nothing to revert (XCP-ng applies changes immediately)'}

    def get_cluster_networks(self):
        """Cluster-wide network overview with VM assignments."""
        api = self._api()
        if not api:
            return []
        try:
            result = []
            for net_ref in api.network.get_all():
                rec = api.network.get_record(net_ref)
                if rec.get('name_label', '').startswith('xapi'):
                    continue
                vif_count = len(rec.get('VIFs', []))
                pif_count = len(rec.get('PIFs', []))
                result.append({
                    'name': rec.get('name_label', ''),
                    'bridge': rec.get('bridge', ''),
                    'uuid': rec.get('uuid', ''),
                    'vif_count': vif_count,
                    'pif_count': pif_count,
                    'mtu': int(rec.get('MTU', 1500)),
                })
            return result
        except Exception as e:
            self.logger.error(f"get_cluster_networks: {e}")
            return []

    # ──────────────────────────────────────────
    # Node reboot / shutdown - XAPI calls
    # ──────────────────────────────────────────

    def reboot_node(self, node_name):
        api, href = self._resolve_host_ref(node_name)
        if not href:
            return {'success': False, 'error': f'Host {node_name} not found'}
        try:
            api.host.disable(href)
            api.Async.host.reboot(href)
            self._cached_nodes = None
            self.logger.info(f"Rebooting host {node_name}")
            return {'success': True, 'message': f'{node_name} rebooting'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def shutdown_node(self, node_name):
        api, href = self._resolve_host_ref(node_name)
        if not href:
            return {'success': False, 'error': f'Host {node_name} not found'}
        try:
            api.host.disable(href)
            api.Async.host.shutdown(href)
            self._cached_nodes = None
            self.logger.info(f"Shutting down host {node_name}")
            return {'success': True, 'message': f'{node_name} shutting down'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # Node updates - yum-based (XCP-ng is CentOS/RHEL)
    # NS/MK Mar 2026
    # ──────────────────────────────────────────

    def start_node_update(self, node_name, reboot=True, force=False):
        """Start async yum update on XCP-ng node."""
        from pegaprox.models.tasks import UpdateTask

        if not force and node_name in self.nodes_in_maintenance:
            return None

        with self.update_lock:
            if node_name in self.nodes_updating:
                existing = self.nodes_updating[node_name]
                if existing.status not in ('completed', 'failed'):
                    return existing  # already running

        task = UpdateTask(node_name, reboot)
        with self.update_lock:
            self.nodes_updating[node_name] = task

        t = threading.Thread(target=self._perform_node_update, daemon=True,
                             args=(node_name, task))
        t.start()
        return task

    def _perform_node_update(self, node_name, task):
        """Background: run yum update via SSH."""
        task.status = 'updating'
        task.phase = 'yum_update'
        task.add_output(f"Starting update on {node_name}...")

        host_ip = self._get_host_ip(node_name)
        ssh = self._ssh_connect(host_ip)
        if not ssh:
            task.status = 'failed'
            task.error = f'SSH connection to {node_name} failed'
            task.add_output(task.error)
            return

        try:
            # phase 1: yum clean + update
            task.add_output("Running yum clean all...")
            _, stdout, stderr = ssh.exec_command("yum clean all 2>&1", timeout=60)
            stdout.channel.recv_exit_status()

            task.phase = 'yum_upgrade'
            task.add_output("Running yum update -y ...")
            _, stdout, stderr = ssh.exec_command("yum update -y 2>&1", timeout=600)
            rc = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='replace')

            pkg_count = 0
            for line in output.splitlines():
                task.add_output(line)
                if 'Updated:' in line or 'Installed:' in line:
                    pkg_count += 1
            task.packages_upgraded = pkg_count

            if rc not in (0, 100):  # yum returns 100 when there are updates
                task.status = 'failed'
                task.error = f'yum update exited with code {rc}'
                task.add_output(f"ERROR: {task.error}")
                return

            # phase 2: reboot if requested
            if task.reboot:
                task.phase = 'reboot'
                task.status = 'rebooting'
                task.add_output(f"Rebooting {node_name}...")
                ssh.exec_command("reboot", timeout=5)
                try:
                    ssh.close()
                except Exception:
                    pass
                ssh = None

                # wait for node
                task.phase = 'wait_online'
                task.status = 'waiting_online'
                task.add_output("Waiting for node to come back online...")
                online = self._wait_for_host_online(node_name, timeout=300)
                if online:
                    task.add_output(f"{node_name} is back online")
                else:
                    task.add_output(f"WARNING: {node_name} did not come back within timeout")

            task.status = 'completed'
            task.phase = 'done'
            from datetime import datetime
            task.completed_at = datetime.now()
            task.add_output("Update completed successfully")
        except Exception as e:
            task.status = 'failed'
            task.error = str(e)
            task.add_output(f"ERROR: {e}")
        finally:
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass

    def _wait_for_host_online(self, node_name, timeout=300):
        """Wait for XCP-ng host to come back after reboot by polling XAPI."""
        import socket
        host_ip = self._get_host_ip(node_name)
        time.sleep(20)  # give it time to shut down

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                sock = socket.create_connection((host_ip, 443), timeout=5)
                sock.close()
                # brief pause then verify XAPI responds
                time.sleep(5)
                api = self._api()
                if api:
                    self._cached_nodes = None
                    return True
            except Exception:
                pass
            time.sleep(10)
        return False

    def get_update_status(self, node_name):
        with self.update_lock:
            if node_name in self.nodes_updating:
                return self.nodes_updating[node_name].to_dict()
        return None

    def clear_update_status(self, node_name):
        with self.update_lock:
            if node_name in self.nodes_updating:
                t = self.nodes_updating[node_name]
                if t.status in ('completed', 'failed'):
                    del self.nodes_updating[node_name]
                    return True
        return False

    def get_node_apt_updates(self, node):
        """List pending updates - yum equivalent of apt updates.
        Returns same field names as Proxmox APT so the frontend renders correctly."""
        rc, out, _ = self._ssh_exec(node, "yum check-update 2>/dev/null", timeout=120)
        # yum check-update returns 100 if updates available, 0 if none
        if rc not in (0, 100):
            return []
        pending = []
        past_header = False
        for line in out.splitlines():
            line = line.strip()
            if not line:
                past_header = True
                continue
            if not past_header:
                continue
            parts = line.split()
            if len(parts) >= 3:
                pending.append((parts[0], parts[1], parts[2]))

        if not pending:
            return []

        # batch query installed versions in one SSH call
        pkg_names = [p[0].rsplit('.', 1)[0] if '.' in p[0] else p[0] for p in pending]
        installed = {}
        try:
            # NS: one rpm call for all packages, pipe-separated output
            cmd = "rpm -q --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' " + ' '.join(pkg_names) + " 2>/dev/null"
            rc2, rpm_out, _ = self._ssh_exec(node, cmd, timeout=30)
            if rc2 == 0:
                for rline in rpm_out.splitlines():
                    rparts = rline.split('\t', 1)
                    if len(rparts) == 2:
                        installed[rparts[0]] = rparts[1]
        except Exception:
            pass

        updates = []
        for pkg_full, new_ver, repo in pending:
            pkg_name = pkg_full.rsplit('.', 1)[0] if '.' in pkg_full else pkg_full
            updates.append({
                'Package': pkg_name,
                'OldVersion': installed.get(pkg_name, ''),
                'Version': new_ver,
                'Origin': repo,
                'Section': 'security' if 'security' in repo.lower() else 'updates',
            })
        return updates

    def refresh_node_apt(self, node):
        """Refresh package cache - yum clean metadata."""
        rc, _, err = self._ssh_exec(node, "yum clean metadata 2>&1 && yum makecache fast 2>&1", timeout=120)
        if rc == 0:
            return {'success': True, 'task': None}
        return {'success': False, 'error': err or 'yum makecache failed'}

    # ──────────────────────────────────────────
    # CVE scanner - yum-based
    # NS Mar 2026 - same output shape as Proxmox (debsecan → yum-plugin-security)
    # ──────────────────────────────────────────

    def scan_node_packages(self, node_name):
        """Scan XCP-ng node for CVEs and pending updates."""
        cmd = """
echo '---OS---'
cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"'
echo '---KERNEL---'
uname -r
echo '---XE---'
xe host-list params=software-version 2>/dev/null | head -5 || echo 'N/A'
echo '---REBOOT---'
if [ -f /var/run/reboot-required ] || needs-restarting -r 2>/dev/null; then echo 'YES'; else echo 'NO'; fi
echo '---CVES---'
yum updateinfo list cves 2>/dev/null || echo 'UNAVAILABLE'
echo '---UPDATES---'
yum check-update 2>/dev/null
echo '---END---'
"""
        rc, out, _ = self._ssh_exec(node_name, cmd.strip(), timeout=120)
        from datetime import datetime
        result = {
            'node': node_name,
            'timestamp': datetime.now().isoformat(),
            'os': '', 'kernel': '', 'pve_version': '',
            'reboot_required': False,
            'debsecan_available': False,
            'cves': [], 'packages': [],
            'cve_count': 0, 'security_count': 0, 'total_count': 0,
        }
        if rc == -1:
            result['error'] = 'SSH connection failed'
            return result

        section = None
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith('---') and stripped.endswith('---'):
                section = stripped.strip('-')
                continue
            if section == 'OS' and stripped:
                result['os'] = stripped
            elif section == 'KERNEL' and stripped:
                result['kernel'] = stripped
            elif section == 'XE' and stripped and stripped != 'N/A':
                result['pve_version'] = stripped  # reusing field name for compat
            elif section == 'REBOOT':
                if 'YES' in stripped.upper():
                    result['reboot_required'] = True
            elif section == 'CVES':
                if stripped == 'UNAVAILABLE':
                    continue
                result['debsecan_available'] = True
                # format: CVE-XXXX-YYYY severity package
                parts = stripped.split()
                if len(parts) >= 3 and parts[0].startswith('CVE-'):
                    result['cves'].append({
                        'cve': parts[0],
                        'package': parts[-1],
                        'urgency': parts[1].lower() if len(parts) > 2 else 'unknown',
                        'status': 'fixed available',
                    })
            elif section == 'UPDATES':
                parts = stripped.split()
                if len(parts) >= 3 and not stripped.startswith('Last') and not stripped.startswith('Loaded'):
                    is_security = 'security' in parts[2].lower() if len(parts) > 2 else False
                    result['packages'].append({
                        'name': parts[0],
                        'current': '',
                        'available': parts[1],
                        'source': parts[2] if len(parts) > 2 else '',
                        'security': is_security,
                        'severity': 'security' if is_security else 'normal',
                    })

        result['cve_count'] = len(result['cves'])
        result['security_count'] = sum(1 for p in result['packages'] if p.get('security'))
        result['total_count'] = len(result['packages'])
        return result

    # ──────────────────────────────────────────
    # CIS Hardening - SSH-based checks
    # MK Mar 2026 - adapted for XCP-ng (CentOS 7.x base)
    # ──────────────────────────────────────────

    # controls mapped to XCP-ng/CentOS equivalents
    _CIS_CHECKS = {
        'fs_modules': {
            'check': "[ -f /etc/modprobe.d/cis-disable-modules.conf ] && echo OK || echo FAIL",
            'apply': """cat > /etc/modprobe.d/cis-disable-modules.conf << 'MODEOF'
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install jffs2 /bin/false
blacklist jffs2
install dccp /bin/false
blacklist dccp
install sctp /bin/false
blacklist sctp
install rds /bin/false
blacklist rds
install tipc /bin/false
blacklist tipc
MODEOF
echo DONE""",
        },
        'core_dumps': {
            'check': """[ -f /etc/systemd/coredump.conf.d/disable-coredump.conf ] && \
grep -q 'hard core 0' /etc/security/limits.conf 2>/dev/null && echo OK || echo FAIL""",
            'apply': """mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable-coredump.conf << 'CDEOF'
[Coredump]
Storage=none
ProcessSizeMax=0
CDEOF
grep -q 'hard core 0' /etc/security/limits.conf 2>/dev/null || echo '* hard core 0' >> /etc/security/limits.conf
echo DONE""",
        },
        'ssh_perms': {
            'check': "stat -c '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '600' && echo OK || echo FAIL",
            'apply': """chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
echo DONE""",
        },
        'ssh_crypto': {
            'check': "grep -q 'CIS SSH Cryptographic Hardening' /etc/ssh/sshd_config 2>/dev/null && echo OK || echo FAIL",
            'apply': """cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.cis
sed -i -e '/^Ciphers /d' -e '/^KexAlgorithms /d' -e '/^MACs /d' \
  -e '/^GSSAPIAuthentication /d' -e '/^HostbasedAuthentication /d' \
  -e '/^IgnoreRhosts /d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config << 'SSHEOF'

# CIS SSH Cryptographic Hardening - applied by PegaProx
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
SSHEOF
sshd -t 2>/dev/null && systemctl restart sshd || { cp /etc/ssh/sshd_config.bak.cis /etc/ssh/sshd_config; systemctl restart sshd; }
echo DONE""",
        },
        'shell_timeout': {
            'check': "grep -q 'TMOUT=900' /etc/profile.d/cis-timeout.sh 2>/dev/null && echo OK || echo FAIL",
            'apply': """cat > /etc/profile.d/cis-timeout.sh << 'TMEOF'
TMOUT=900
readonly TMOUT
export TMOUT
TMEOF
chmod 644 /etc/profile.d/cis-timeout.sh
echo DONE""",
        },
        'file_perms': {
            'check': "stat -c '%a' /etc/passwd 2>/dev/null | grep -q '644' && stat -c '%a' /etc/shadow 2>/dev/null | grep -qE '(640|600)' && echo OK || echo FAIL",
            'apply': """chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null
chown root:root /etc/passwd /etc/group
chown root:shadow /etc/shadow 2>/dev/null
echo DONE""",
        },
        'journald': {
            'check': "[ -f /etc/systemd/journald.conf.d/99-cis-hardening.conf ] && echo OK || echo FAIL",
            'apply': """mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-cis-hardening.conf << 'JDEOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=no
JDEOF
systemctl restart systemd-journald
echo DONE""",
        },
        'pw_aging': {
            'check': "grep -q 'PASS_MAX_DAYS.*365' /etc/login.defs && echo OK || echo FAIL",
            'apply': """sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   30/' /etc/login.defs
chage -M -1 root 2>/dev/null
chage -m 0 root 2>/dev/null
echo DONE""",
        },
        'default_umask': {
            'check': "(grep -q 'UMASK.*027' /etc/login.defs 2>/dev/null || grep -q 'umask 027' /etc/profile 2>/dev/null) && echo OK || echo FAIL",
            'apply': """if grep -q '^UMASK' /etc/login.defs 2>/dev/null; then
  sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
else
  echo 'UMASK           027' >> /etc/login.defs
fi
grep -q '^umask 027' /etc/profile || echo 'umask 027' >> /etc/profile
echo DONE""",
        },
        'firewall': {
            'check': "systemctl is-active iptables 2>/dev/null | grep -q active && echo OK || systemctl is-active firewalld 2>/dev/null | grep -q active && echo OK || echo FAIL",
            'apply': "echo 'Manual: enable iptables or firewalld and configure rules'; echo DONE",
        },
    }

    def check_node_hardening(self, node_name):
        """Run CIS checks on XCP-ng host and return status per control."""
        parts = []
        for cid, spec in self._CIS_CHECKS.items():
            parts.append(f"echo '---{cid}---'")
            parts.append(spec['check'])
        cmd = '; '.join(parts)

        rc, out, _ = self._ssh_exec(node_name, cmd, timeout=60)
        if rc == -1:
            return None

        results = {}
        current_id = None
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith('---') and stripped.endswith('---'):
                current_id = stripped.strip('-')
                continue
            if current_id and stripped in ('OK', 'FAIL'):
                results[current_id] = (stripped == 'OK')
        return results

    def apply_node_hardening(self, node_name, controls):
        """Apply selected CIS controls via SSH."""
        results = {}
        for cid in controls:
            spec = self._CIS_CHECKS.get(cid)
            if not spec:
                results[cid] = {'success': False, 'error': f'Unknown control: {cid}'}
                continue
            rc, out, _ = self._ssh_exec(node_name, spec['apply'], timeout=60)
            if 'DONE' in out:
                results[cid] = {'success': True}
                self.logger.info(f"[CIS] Applied {cid} on {node_name}")
            else:
                results[cid] = {'success': False, 'error': out.strip()[-200:] if out else 'No output'}
        return results

    # ──────────────────────────────────────────
    # Node disks & storage repos - NS/LW Mar 2026
    # ──────────────────────────────────────────

    def get_node_disks(self, node):
        """List physical disks on a node via lsblk. Returns same-ish shape as Proxmox."""
        # LW: validate node name against injection
        if not re.match(r'^[a-zA-Z0-9\-_.]+$', node):
            return []
        rc, out, _ = self._ssh_exec(node,
            "lsblk -J -b -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,ROTA,TRAN,FSTYPE 2>/dev/null")
        if rc != 0 or not out.strip():
            return []
        try:
            import json as _json
            data = _json.loads(out)
        except Exception:
            return []

        disks = []
        for dev in data.get('blockdevices', []):
            if dev.get('type') not in ('disk',):
                continue
            name = dev.get('name', '')
            size = int(dev.get('size', 0) or 0)
            transport = dev.get('tran', '') or ''
            rotational = dev.get('rota', True)

            # figure out disk type
            if 'nvme' in name or transport == 'nvme':
                disk_type = 'nvme'
            elif not rotational or transport == 'sata' and size < 4 * 1024**4:
                disk_type = 'ssd'
            else:
                disk_type = 'hdd'

            # check if disk is in use
            in_use = False
            children = dev.get('children', [])
            if children:
                in_use = True
            # also check mountpoint and fstype on the disk itself
            if dev.get('mountpoint') or dev.get('fstype'):
                in_use = True

            disks.append({
                'devpath': f'/dev/{name}',
                'name': name,
                'size': size,
                'model': (dev.get('model') or '').strip(),
                'serial': (dev.get('serial') or '').strip(),
                'type': disk_type,
                'transport': transport,
                'used': in_use,
                'mounted': dev.get('mountpoint', ''),
                'fstype': dev.get('fstype', ''),
                'partitions': len(children),
            })
        return disks

    def get_node_disk_smart(self, node, disk):
        """SMART data for a specific disk."""
        # validate disk path to prevent injection
        if not re.match(r'^(sd[a-z]+|nvme\d+n\d+|hd[a-z]+|vd[a-z]+)$', disk):
            return {'error': f'Invalid disk name: {disk}'}
        rc, out, err = self._ssh_exec(node, f"smartctl -a /dev/{disk} --json 2>/dev/null", timeout=30)
        if rc == -1:
            return {'error': 'SSH connection failed'}
        try:
            import json as _json
            return _json.loads(out)
        except Exception:
            # smartctl sometimes returns non-zero but valid output
            return {'raw': out[:2000], 'error': err[:500] if err else None}

    def init_disk_gpt(self, node, disk, uuid=None):
        """Initialize disk with GPT partition table. DESTRUCTIVE."""
        if not re.match(r'^(sd[a-z]+|nvme\d+n\d+|hd[a-z]+|vd[a-z]+)$', disk):
            return {'success': False, 'error': f'Invalid disk: {disk}'}
        # NS: sgdisk -Z wipes existing, -o creates fresh GPT
        rc, out, err = self._ssh_exec(node,
            f"sgdisk -Z /dev/{disk} && sgdisk -o /dev/{disk}", timeout=30)
        if rc == 0:
            return {'success': True, 'message': f'GPT initialized on /dev/{disk}'}
        return {'success': False, 'error': err or 'sgdisk failed'}

    def wipe_disk(self, node, disk):
        if not re.match(r'^(sd[a-z]+|nvme\d+n\d+|hd[a-z]+|vd[a-z]+)$', disk):
            return {'success': False, 'error': f'Invalid disk: {disk}'}
        rc, _, err = self._ssh_exec(node, f"wipefs -a /dev/{disk}", timeout=30)
        if rc == 0:
            return {'success': True, 'message': f'/dev/{disk} wiped'}
        return {'success': False, 'error': err or 'wipefs failed'}

    def _resolve_host(self, node_name):
        """Resolve node name to XAPI host ref. Used by SR creation etc."""
        api = self._api()
        if not api:
            return None, None
        for href in api.host.get_all():
            try:
                hn = api.host.get_hostname(href)
                if hn == node_name or api.host.get_name_label(href) == node_name:
                    return api, href
            except Exception:
                continue
        return api, None

    def create_sr_nfs(self, node, name, server, path, nfsversion='3'):
        """Create shared NFS storage repository."""
        api, host_ref = self._resolve_host(node)
        if not host_ref:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            device_config = {
                'server': server,
                'serverpath': path,
            }
            if nfsversion and nfsversion != '3':
                device_config['nfsversion'] = str(nfsversion)

            sr_ref = api.SR.create(
                host_ref, device_config, '0',  # physical_size=0 means auto-detect
                name, '', 'nfs', '',  # content_type
                True,  # shared
                {}     # sm_config
            )
            sr_uuid = api.SR.get_uuid(sr_ref)
            self.logger.info(f"Created NFS SR '{name}' on {node}: {server}:{path}")
            self._cached_nodes = None
            return {'success': True, 'uuid': sr_uuid}
        except Exception as e:
            self.logger.error(f"create_sr_nfs: {e}")
            return {'success': False, 'error': str(e)}

    def create_sr_iscsi(self, node, name, target, iqn, scsi_id, port=3260,
                        chap_user='', chap_pass=''):
        """Create shared iSCSI SR (LVM over iSCSI)."""
        api, host_ref = self._resolve_host(node)
        if not host_ref:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            device_config = {
                'target': target,
                'targetIQN': iqn,
                'SCSIid': scsi_id,
                'port': str(port),
            }
            if chap_user:
                device_config['chapuser'] = chap_user
                device_config['chappassword'] = chap_pass

            sr_ref = api.SR.create(
                host_ref, device_config, '0',
                name, '', 'lvmoiscsi', '',
                True, {}
            )
            uuid = api.SR.get_uuid(sr_ref)
            self.logger.info(f"Created iSCSI SR '{name}' -> {target}")
            self._cached_nodes = None
            return {'success': True, 'uuid': uuid}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_sr_lvm(self, node, name, device):
        """Create local LVM SR on a specific disk."""
        # MK: validate device path
        if not re.match(r'^/dev/[a-zA-Z0-9/]+$', device):
            return {'success': False, 'error': f'Invalid device path: {device}'}
        api, host_ref = self._resolve_host(node)
        if not host_ref:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            sr_ref = api.SR.create(
                host_ref, {'device': device}, '0',
                name, '', 'lvm', '',
                False, {}  # local, not shared
            )
            uuid = api.SR.get_uuid(sr_ref)
            self.logger.info(f"Created LVM SR '{name}' on {device}")
            self._cached_nodes = None
            return {'success': True, 'uuid': uuid}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_sr_ext(self, node, name, device):
        """Local EXT SR - simpler than LVM, good for single-disk setups."""
        if not re.match(r'^/dev/[a-zA-Z0-9/]+$', device):
            return {'success': False, 'error': f'Invalid device: {device}'}
        api, host_ref = self._resolve_host(node)
        if not host_ref:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            sr_ref = api.SR.create(
                host_ref, {'device': device}, '0',
                name, '', 'ext', '',
                False, {}
            )
            self._cached_nodes = None
            return {'success': True, 'uuid': api.SR.get_uuid(sr_ref)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def discover_iscsi(self, node, target, port=3260):
        """Probe iSCSI target for available IQNs and LUNs."""
        # NS May 2026: defusedxml here too — probe_result is whatever the
        # iSCSI target returned, which is *not* something we control.
        # hoisted ahead of api.SR.probe() so the outer-except parse path below
        # (XAPI throws with LUN info — that *is* the common case) can also use ET.
        from defusedxml import ElementTree as ET
        api, host_ref = self._resolve_host(node)
        if not host_ref:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            # phase 1: discover IQNs
            probe_result = api.SR.probe(
                host_ref,
                {'target': target, 'port': str(port)},
                'lvmoiscsi', {}
            )
            # probe returns XML - parse IQNs
            iqns = []
            try:
                root = ET.fromstring(probe_result)
                for tgt in root.findall('.//TGT'):
                    iqn_el = tgt.find('TargetIQN')
                    ip_el = tgt.find('IPAddress')
                    if iqn_el is not None:
                        iqns.append({
                            'iqn': iqn_el.text,
                            'ip': ip_el.text if ip_el is not None else target,
                        })
            except ET.ParseError:
                pass
            return {'success': True, 'iqns': iqns}
        except Exception as e:
            # XAPI throws an exception with LUN info when IQN is provided
            err_str = str(e)
            if 'SCSIid' in err_str:
                # this means probe succeeded, parse LUNs from the error XML
                luns = []
                try:
                    root = ET.fromstring(err_str)
                    for lun in root.findall('.//LUN'):
                        scsi_el = lun.find('SCSIid')
                        size_el = lun.find('size')
                        if scsi_el is not None:
                            luns.append({
                                'scsi_id': scsi_el.text,
                                'size': int(size_el.text) if size_el is not None else 0,
                            })
                except Exception:
                    pass
                return {'success': True, 'luns': luns}
            return {'success': False, 'error': str(e)}

    # compat wrappers for Proxmox-style API dispatch
    def create_node_lvm(self, node, name, device):
        return self.create_sr_lvm(node, name, device)

    def get_node_lvm(self, node):
        """Return SRs that look like LVM storages - for API compat."""
        storages = self.get_storages(node)
        return [s for s in storages if s.get('type') in ('lvm', 'lvmoiscsi', 'lvmohba')]

    # ──────────────────────────────────────────
    # Resource pools - DB-backed (XAPI has no equivalent)
    # LW Mar 2026 - lightweight pool feature for XCP-ng
    # ──────────────────────────────────────────

    def get_pools(self):
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT poolid, comment FROM xcpng_pools WHERE cluster_id = ?', (self.id,))
        return [{'poolid': r[0], 'comment': r[1] or ''} for r in cursor.fetchall()]

    def get_pool_members(self, pool_id):
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT vmid FROM xcpng_pool_members WHERE cluster_id = ? AND poolid = ?',
                       (self.id, pool_id))
        vmids = [r[0] for r in cursor.fetchall()]
        members = []
        for vmid in vmids:
            # find VM in cache for name
            vm = next((v for v in (self._cached_vms or []) if v.get('vmid') == vmid), None)
            members.append({
                'vmid': vmid,
                'type': 'qemu',
                'name': vm.get('name', '') if vm else '',
                'status': vm.get('status', '') if vm else '',
            })
        return {'poolid': pool_id, 'members': members}

    def get_vm_pool(self, vmid, vm_type='qemu'):
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT poolid FROM xcpng_pool_members WHERE cluster_id = ? AND vmid = ?',
                       (self.id, int(vmid)))
        row = cursor.fetchone()
        return row[0] if row else None

    def create_pool(self, poolid, comment=''):
        db = get_db()
        try:
            cursor = db.conn.cursor()
            cursor.execute('INSERT INTO xcpng_pools (cluster_id, poolid, comment) VALUES (?, ?, ?)',
                           (self.id, poolid, comment))
            db.conn.commit()
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def update_pool(self, poolid, comment='', members_to_add=None, members_to_remove=None):
        db = get_db()
        cursor = db.conn.cursor()
        try:
            if comment is not None:
                cursor.execute('UPDATE xcpng_pools SET comment = ? WHERE cluster_id = ? AND poolid = ?',
                               (comment, self.id, poolid))
            if members_to_add:
                for vmid in members_to_add:
                    cursor.execute('INSERT OR IGNORE INTO xcpng_pool_members (cluster_id, poolid, vmid) VALUES (?, ?, ?)',
                                   (self.id, poolid, int(vmid)))
            if members_to_remove:
                for vmid in members_to_remove:
                    cursor.execute('DELETE FROM xcpng_pool_members WHERE cluster_id = ? AND poolid = ? AND vmid = ?',
                                   (self.id, poolid, int(vmid)))
            db.conn.commit()
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def delete_pool(self, poolid):
        db = get_db()
        try:
            cursor = db.conn.cursor()
            # check for members
            cursor.execute('SELECT COUNT(*) FROM xcpng_pool_members WHERE cluster_id = ? AND poolid = ?',
                           (self.id, poolid))
            cnt = cursor.fetchone()[0]
            if cnt > 0:
                return {'success': False, 'error': f'Pool not empty - contains {cnt} members'}
            cursor.execute('DELETE FROM xcpng_pools WHERE cluster_id = ? AND poolid = ?', (self.id, poolid))
            db.conn.commit()
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # Cross-pool migration - XAPI VM.migrate_send
    # NS Mar 2026 - requires network connectivity between pools
    # ──────────────────────────────────────────

    def remote_migrate_vm(self, node, vmid, vm_type='qemu', target_endpoint=None,
                          target_storage=None, target_bridge=None, target_vmid=None,
                          online=True, delete_source=True, bwlimit=None):
        """Migrate VM to another XCP-ng pool via XAPI migrate_send.

        target_endpoint: https://<remote_host> of the target pool master
        """
        if not target_endpoint:
            return {'success': False, 'error': 'Target endpoint required'}

        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}

        try:
            vm_ref = self._resolve_vm(vmid)
            power = api.VM.get_power_state(vm_ref)

            # connect to remote pool to get session
            remote_session = XenAPI.Session(target_endpoint, ignore_ssl=True)
            remote_session.xenapi.login_with_password(
                self.config.user, self.config.pass_, '1.0', 'PegaProx')

            # build migrate_send params
            dest = {
                'force': 'true',
            }
            # add session ref for auth
            dest['session_id'] = remote_session._session

            # live or offline?
            live = online and power == 'Running'

            if live:
                # live migrate across pools
                # NS: XAPI wants a dict with destination host/network info
                dest_host_refs = remote_session.xenapi.host.get_all()
                if not dest_host_refs:
                    return {'success': False, 'error': 'No hosts in target pool'}
                dest['host'] = dest_host_refs[0]  # pool master
                # vdi_map and vif_map can be empty for default mapping
                task_ref = api.Async.VM.migrate_send(vm_ref, dest, live, {}, {}, {})
            else:
                if power != 'Halted':
                    api.VM.hard_shutdown(vm_ref)
                    time.sleep(3)
                # for offline, use VM.copy to remote SR
                # this is more like clone+transfer
                task_ref = api.Async.VM.copy(vm_ref, f'migrated-{vmid}', 'OpaqueRef:NULL')

            task_id = self._track_task(task_ref, 'remote_migrate', vmid)

            try:
                remote_session.xenapi.session.logout()
            except Exception:
                pass

            self.logger.info(f"Remote migration started: VM {vmid} -> {target_endpoint}")
            return {'success': True, 'task': task_id}
        except Exception as e:
            self.logger.error(f"remote_migrate_vm {vmid}: {e}")
            return {'success': False, 'error': str(e)}

    # ──────────────────────────────────────────
    # Additional node info stubs
    # ──────────────────────────────────────────

    def get_node_summary(self, node):
        """Node summary - same as get_node_details but flatter."""
        return self.get_node_details(node)

    def get_node_syslog(self, node, start=0, limit=500):
        """Fetch recent syslog entries via SSH."""
        rc, out, _ = self._ssh_exec(node,
            f"journalctl --no-pager -n {limit} --output=short-iso 2>/dev/null || tail -n {limit} /var/log/messages 2>/dev/null",
            timeout=15)
        if rc != 0 or not out:
            return []
        lines = out.strip().splitlines()
        return [{'n': i + start, 't': line} for i, line in enumerate(lines)]

    def get_node_certificates(self, node):
        """Read xapi-ssl.pem certificate info."""
        rc, out, _ = self._ssh_exec(node,
            "openssl x509 -in /etc/xensource/xapi-ssl.pem -noout -subject -enddate -issuer 2>/dev/null")
        if rc != 0:
            return []
        info = {}
        for line in out.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                info[k.strip().lower()] = v.strip()
        return [{
            'filename': 'xapi-ssl.pem',
            'subject': info.get('subject', ''),
            'issuer': info.get('issuer', ''),
            'notafter': info.get('notafter', ''),
            'fingerprint': '',
            'san': [],
        }]

    def renew_node_certificate(self, node, force=False):
        """Generate fresh self-signed cert for XAPI.
        XCP-ng has no ACME — so 'renew' means regenerate self-signed."""
        host_ip = self._get_host_ip(node)
        # backup before touching the pem - if openssl craps out xapi won't start
        self._ssh_exec(node, "cp /etc/xensource/xapi-ssl.pem /etc/xensource/xapi-ssl.pem.bak 2>/dev/null")
        # NS: xapi expects combined pem, 10yr validity should be fine
        gen_cmd = (
            "openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
            "-keyout /etc/xensource/xapi-ssl.pem "
            "-out /etc/xensource/xapi-ssl.pem "
            "-subj '/CN=%s' 2>&1" % host_ip
        )
        rc, out, err = self._ssh_exec(node, gen_cmd, timeout=30)
        if rc != 0:
            self._ssh_exec(node, "mv /etc/xensource/xapi-ssl.pem.bak /etc/xensource/xapi-ssl.pem 2>/dev/null")
            return {'success': False, 'error': err or out or 'openssl failed'}

        rc2, _, err2 = self._ssh_exec(node, "systemctl restart xapi 2>&1", timeout=45)
        if rc2 != 0:
            self.logger.warning(f"cert renewed but xapi restart failed on {node}: {err2}")
            return {'success': True, 'message': 'Certificate renewed but XAPI restart failed — restart manually'}
        # cleanup backup on success
        self._ssh_exec(node, "rm -f /etc/xensource/xapi-ssl.pem.bak 2>/dev/null")
        return {'success': True, 'message': 'Certificate renewed'}

    def upload_node_certificate(self, node, certificates, key, restart=True, force=False):
        """Upload custom cert+key to XCP-ng node via SSH."""
        if not certificates or not key:
            return {'success': False, 'error': 'Certificate and key required'}
        # combine cert + key into single PEM (xapi wants both in one file)
        combined = certificates.strip() + '\n' + key.strip() + '\n'
        # backup current cert first
        self._ssh_exec(node, "cp /etc/xensource/xapi-ssl.pem /etc/xensource/xapi-ssl.pem.bak 2>/dev/null")
        # Use random delimiter to prevent heredoc terminator injection
        delimiter = f"EOF_{_uuid.uuid4().hex}"
        rc, _, err = self._ssh_exec(node,
            f"cat > /etc/xensource/xapi-ssl.pem << '{delimiter}'\n{combined}{delimiter}")
        if rc != 0:
            return {'success': False, 'error': err or 'Failed to write certificate'}

        # validate the cert is readable
        rc_v, _, _ = self._ssh_exec(node,
            "openssl x509 -in /etc/xensource/xapi-ssl.pem -noout -subject 2>&1")
        if rc_v != 0:
            # rollback
            self._ssh_exec(node, "mv /etc/xensource/xapi-ssl.pem.bak /etc/xensource/xapi-ssl.pem 2>/dev/null")
            return {'success': False, 'error': 'Invalid certificate — rolled back'}

        if restart:
            rc_r, _, err_r = self._ssh_exec(node, "systemctl restart xapi 2>&1", timeout=45)
            if rc_r != 0:
                return {'success': True, 'message': 'Certificate uploaded but XAPI restart failed'}
        return {'success': True, 'message': 'Certificate uploaded successfully'}

    def delete_node_certificate(self, node, restart=True):
        """Revert to self-signed certificate (same as renew for XCP-ng)."""
        return self.renew_node_certificate(node, force=True)

    def get_node_subscription(self, node):
        return {}

    def update_node_subscription(self, node, key):
        return {'success': False, 'error': 'Subscription management not applicable for XCP-ng'}

    def get_node_replication(self, node):
        return []

    def get_node_tasks(self, node, start=0, limit=50, errors=False):
        """Return tasks filtered by node."""
        tasks = self.get_tasks(limit=limit)
        return tasks  # all tasks are pool-wide anyway

    def get_node_task_log(self, node, upid, start=0, limit=50):
        return self.get_task_log(node, upid, limit)

    # ──────────────────────────────────────────
    # Proxmox-specific stubs (no-ops for XCP-ng)
    # NS: these exist so the API layer doesn't crash on XCP-ng clusters
    # ──────────────────────────────────────────

    def _create_session(self):
        """Compat stub - PegaProxManager returns a requests.Session. We don't need this."""
        return None

    # NS: get_pools / get_pool_members moved to resource pools section above (DB-backed)

    def get_next_vmid(self) -> dict:
        """Return next available VMID from our xcpng_vmid_map sequence."""
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute('SELECT MAX(vmid) FROM xcpng_vmid_map WHERE cluster_id = ?', (self.id,))
            row = cursor.fetchone()
            next_id = (row[0] or 99) + 1
            return {'success': True, 'vmid': next_id}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_node_shell_ticket(self, node):
        """Return SSH connection info for the web terminal.
        NS Mar 2026 - the SSH websocket server is hypervisor-agnostic, just give it the IP."""
        node_ip = self._get_host_ip(node)
        return {
            'success': True,
            'type': 'ssh',
            'host': node_ip,
            'port': getattr(self.config, 'ssh_port', 22) or 22,
            'node': node,
        }

    def get_vm_lock_status(self, node, vmid, vm_type='qemu'):
        """XCP-ng VMs use XAPI locks internally, not user-visible like Proxmox."""
        try:
            ref = self._resolve_vm(vmid)
            api = self._api()
            if not api:
                return {'success': False, 'error': 'Not connected'}
            ops = api.VM.get_current_operations(ref)
            if ops:
                return {'success': True, 'locked': True, 'lock_reason': 'operation',
                        'lock_description': f'Active operations: {", ".join(ops.values())}'}
            return {'success': True, 'locked': False, 'lock_reason': None, 'lock_description': None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def unlock_vm(self, node, vmid, vm_type='qemu'):
        """Cancel pending operations on XCP-ng VM. Not a direct equivalent to Proxmox unlock."""
        try:
            ref = self._resolve_vm(vmid)
            api = self._api()
            if not api:
                return {'success': False, 'error': 'Not connected'}
            ops = api.VM.get_current_operations(ref)
            if not ops:
                return {'success': True, 'message': 'VM has no active operations', 'was_locked': False}
            # can't really cancel XAPI ops the same way, but report the state
            return {'success': True, 'message': 'XCP-ng operations are managed by XAPI', 'was_locked': bool(ops),
                    'lock_reason': ', '.join(ops.values()) if ops else None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_iso_list(self, node, storage=None):
        """List ISOs on ISO-type SRs."""
        api = self._api()
        if not api:
            return []
        try:
            isos = []
            for sr_ref in api.SR.get_all():
                sr_type = api.SR.get_type(sr_ref)
                if sr_type != 'iso':
                    continue
                sr_name = api.SR.get_name_label(sr_ref)
                if storage and sr_name != storage:
                    continue
                for vdi_ref in api.SR.get_VDIs(sr_ref):
                    rec = api.VDI.get_record(vdi_ref)
                    isos.append({
                        'volid': f"{sr_name}:iso/{rec.get('name_label', '')}",
                        'name': rec.get('name_label', ''),
                        'size': int(rec.get('virtual_size', 0)),
                        'uuid': rec.get('uuid', ''),
                    })
            return isos
        except Exception as e:
            self.logger.error(f"get_iso_list: {e}")
            return []

    # ──────────────────────────────────────────
    # Proxmox-only stubs - prevent AttributeError on XCP-ng clusters
    # These are called by the API/background layers without type checks
    # ──────────────────────────────────────────

    def sanitize_boot_order(self, node, vmid, vm_type='qemu'):
        pass  # Proxmox-specific, XCP-ng handles boot order differently

    def update_node_options(self, node, options):
        """Store node options in XAPI host.other_config."""
        if not options:
            return {'success': True, 'message': 'Nothing to update'}
        api, href = self._resolve_host_ref(node)
        if not href:
            return {'success': False, 'error': f'Host {node} not found'}
        try:
            for k, v in options.items():
                api.host.add_to_other_config(href, f'pegaprox:{k}', str(v))
            return {'success': True, 'message': 'Options updated'}
        except Exception as e:
            self.logger.error(f"update_node_options {node}: {e}")
            return {'success': False, 'error': str(e)}

    def get_storage_list(self, node=None):
        """Alias for get_storages - Proxmox API compat."""
        return self.get_storages(node)

    def get_network_list(self, node=None):
        return self.get_networks(node)

    def toggle_network_link(self, node, vmid, net_id, link_down):
        """Plug/unplug a VIF to simulate cable disconnect."""
        api = self._api()
        if not api:
            return {'success': False, 'error': 'Not connected'}
        try:
            ref = self._resolve_vm(vmid)
            vifs = api.VM.get_VIFs(ref)

            target = None
            for vif_ref in vifs:
                if api.VIF.get_device(vif_ref) == str(net_id):
                    target = vif_ref
                    break
            if not target:
                return {'success': False, 'error': f'VIF {net_id} not found'}

            power = api.VM.get_power_state(ref)
            if power != 'Running':
                return {'success': False, 'error': 'VM must be running to toggle link'}

            attached = api.VIF.get_currently_attached(target)
            if link_down and not attached:
                return {'success': True, 'message': f'Network {net_id} already disconnected'}
            if not link_down and attached:
                return {'success': True, 'message': f'Network {net_id} already connected'}

            if link_down:
                api.VIF.unplug(target)
            else:
                api.VIF.plug(target)

            state_str = 'disconnected' if link_down else 'connected'
            return {'success': True, 'message': f'Network {net_id} {state_str}'}
        except Exception as e:
            self.logger.error(f"toggle_network_link {vmid}/{net_id}: {e}")
            return {'success': False, 'error': str(e)}

    def check_snapshot_capability(self, node, vmid, vm_type='qemu'):
        return {'capable': True, 'reason': ''}

    # efficient snapshots - Proxmox LVM feature, not applicable to XCP-ng
    def get_efficient_snapshots(self, cluster_id, vmid, refresh_usage=False):
        return []

    def create_efficient_snapshot(self, node, vmid, vm_type, snapname, description='', snap_size_gb=0):
        return {'success': False, 'error': 'Efficient snapshots are a Proxmox-only feature. Use standard snapshots.'}

    def delete_efficient_snapshot(self, node, vmid, snap_id):
        return {'success': False, 'error': 'Efficient snapshots not available on XCP-ng'}

    def rollback_efficient_snapshot(self, node, vmid, vm_type, snap_id):
        return {'success': False, 'error': 'Efficient snapshots not available on XCP-ng'}

    # replication - Proxmox ZFS feature
    def get_replication_jobs(self, node=None):
        return []

    def create_replication_job(self, node, vmid, target, schedule='*/15', rate=None, comment=''):
        return {'success': False, 'error': 'Replication jobs are a Proxmox ZFS feature'}

    def delete_replication_job(self, job_id):
        return {'success': False, 'error': 'No replication jobs on XCP-ng'}

    def run_replication_now(self, job_id):
        return {'success': False, 'error': 'No replication jobs on XCP-ng'}

    # hardware option lists for VM create wizard
    def get_cpu_types(self):
        return ['host', 'max']  # XCP-ng uses host passthrough by default

    def get_scsi_controllers(self):
        return []  # XCP-ng uses PV drivers, no SCSI controller selection

    def get_network_models(self):
        return ['e1000', 'rtl8139', 'netfront']

    def get_disk_bus_types(self):
        return ['xvd', 'hd']  # Xen virtual block devices

    def get_cache_modes(self):
        return ['none', 'writethrough', 'writeback']

    def get_machine_types(self):
        return ['hvm', 'pv']  # Xen HVM or paravirtualized

    # HA stubs - XCP-ng has pool HA but different interface
    def start_ha_monitor(self):
        pass  # XCP-ng HA is managed by XAPI, no separate monitor needed

    def stop_ha_monitor(self):
        pass

    def add_vm_to_proxmox_ha(self, node, vmid, vm_type='qemu', group=None, max_restart=1, max_relocate=1):
        """Use set_vm_ha_restart_priority instead for XCP-ng."""
        return self.set_vm_ha_restart_priority(vmid, 'restart')

    def remove_vm_from_proxmox_ha(self, node, vmid, vm_type='qemu'):
        return self.set_vm_ha_restart_priority(vmid, '')

    # ──────────────────────────────────────────
    # Load balancing - MK/NS Mar 2026
    # Port from manager.py with XCP-ng specifics (shared storage check etc)
    # ──────────────────────────────────────────

    def set_vm_balancing_excluded(self, vmid, excluded, vm_type='qemu'):
        db = get_db()
        try:
            cursor = db.conn.cursor()
            if excluded:
                cursor.execute(
                    'INSERT OR IGNORE INTO balancing_excluded_vms (cluster_id, vmid) VALUES (?, ?)',
                    (self.id, int(vmid)))
            else:
                cursor.execute(
                    'DELETE FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                    (self.id, int(vmid)))
            db.conn.commit()
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def is_vm_balancing_excluded(self, vmid):
        db = get_db()
        try:
            cursor = db.conn.cursor()
            cursor.execute('SELECT 1 FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                           (self.id, int(vmid)))
            return cursor.fetchone() is not None
        except Exception:
            return False

    def get_balancing_excluded_vms(self):
        db = get_db()
        try:
            cursor = db.conn.cursor()
            cursor.execute('SELECT vmid FROM balancing_excluded_vms WHERE cluster_id = ?', (self.id,))
            return [r[0] for r in cursor.fetchall()]
        except Exception:
            return []

    def check_balance_needed(self, node_status=None):
        """Check if cluster is imbalanced. Returns (needs_balance, max_node, min_node)."""
        if not node_status:
            node_status = self.get_node_status()
        if len(node_status) < 2:
            return False, None, None

        threshold = getattr(self.config, 'migration_threshold', 30)

        # filter: online, not in maintenance, not excluded
        active = {}
        for name, info in node_status.items():
            if info.get('offline') or info.get('maintenance_mode'):
                continue
            active[name] = info

        if len(active) < 2:
            return False, None, None

        scores = {n: info.get('score', 0) for n, info in active.items()}
        max_node = max(scores, key=scores.get)
        min_node = min(scores, key=scores.get)
        diff = scores[max_node] - scores[min_node]

        if diff > threshold:
            return True, max_node, min_node
        return False, None, None

    def check_vm_storage_type(self, node, vmid):
        """Check if VM's storage is shared (required for live migration).
        Returns 'shared', 'local', or 'mixed'."""
        api = self._api()
        if not api:
            return 'local'
        try:
            ref = self._resolve_vm(vmid)
            shared_count = 0
            local_count = 0
            for vbd_ref in api.VM.get_VBDs(ref):
                rec = api.VBD.get_record(vbd_ref)
                if rec.get('type') != 'Disk':
                    continue
                vdi = rec.get('VDI', 'OpaqueRef:NULL')
                if vdi == 'OpaqueRef:NULL':
                    continue
                sr = api.VDI.get_SR(vdi)
                if api.SR.get_shared(sr):
                    shared_count += 1
                else:
                    local_count += 1
            if local_count == 0 and shared_count > 0:
                return 'shared'
            if shared_count == 0:
                return 'local'
            return 'mixed'
        except Exception:
            return 'local'

    def find_migration_candidate(self, source_node, target_node=None, exclude_vmids=None):
        """Find best VM to migrate from source_node.
        Prefers VMs on shared storage (live-migratable), then smallest memory."""
        if not exclude_vmids:
            exclude_vmids = set()
        excluded_vms = set(self.get_balancing_excluded_vms()) | set(exclude_vmids)

        vms = self._cached_vms or self.get_vms() or []
        candidates = []
        for vm in vms:
            if vm.get('status') != 'running':
                continue
            if vm.get('node') != source_node:
                continue
            vid = vm.get('vmid')
            if vid in excluded_vms:
                continue
            # check storage
            st_type = self.check_vm_storage_type(source_node, vid)
            candidates.append({
                'vmid': vid,
                'name': vm.get('name', ''),
                'mem': vm.get('mem', 0),
                'storage_type': st_type,
                'node': source_node,
            })

        if not candidates:
            return None

        # sort: shared storage first, then smallest memory
        candidates.sort(key=lambda c: (0 if c['storage_type'] == 'shared' else 1, c['mem']))
        return candidates[0]

    def get_best_target_node(self, exclude_nodes=None):
        """Pick the least loaded node."""
        node_status = self.get_node_status()
        if not exclude_nodes:
            exclude_nodes = set()
        best = None
        best_score = float('inf')
        for name, info in node_status.items():
            if name in exclude_nodes:
                continue
            if info.get('offline') or info.get('maintenance_mode'):
                continue
            s = info.get('score', 999)
            if s < best_score:
                best_score = s
                best = name
        return best

    def _do_balance_migrate(self, vm_info, target_node):
        """Execute a single balancing migration. Returns True on success."""
        vmid = vm_info['vmid']
        source = vm_info['node']
        try:
            self.logger.info(f"[BALANCE] migrating VM {vmid} ({vm_info.get('name','')}) "
                             f"{source} -> {target_node}")
            result = self.migrate_vm_manual(source, vmid, 'qemu', target_node=target_node, online=True)
            if result.get('success'):
                self.last_migration_log.append({
                    'ts': time.time(),
                    'vmid': vmid,
                    'from': source,
                    'to': target_node,
                    'reason': 'auto_balance',
                })
                # keep log short
                if len(self.last_migration_log) > 50:
                    self.last_migration_log = self.last_migration_log[-50:]
                return True
            else:
                self.logger.warning(f"[BALANCE] migration failed: {result.get('error')}")
        except Exception as e:
            self.logger.error(f"[BALANCE] migrate VM {vmid}: {e}")
        return False

    def run_balance_check(self):
        """Main balancing cycle - called from _run_loop."""
        node_status = self.get_node_status()
        if not node_status:
            return

        needs, max_node, min_node = self.check_balance_needed(node_status)
        if not needs:
            return

        self.logger.info(f"[BALANCE] imbalance detected: {max_node} (overloaded) vs {min_node}")

        # max migrations per cycle depends on cluster size
        num_nodes = len([n for n in node_status.values() if not n.get('offline')])
        max_migrations = min(3, max(1, num_nodes // 2))
        migrated = 0
        already_tried = set()

        for _ in range(max_migrations):
            candidate = self.find_migration_candidate(max_node, min_node, already_tried)
            if not candidate:
                break

            already_tried.add(candidate['vmid'])

            # only live-migrate shared storage VMs
            if candidate['storage_type'] != 'shared':
                self.logger.info(f"[BALANCE] skipping VM {candidate['vmid']} - local storage")
                continue

            target = min_node or self.get_best_target_node(exclude_nodes={max_node})
            if not target:
                break

            ok = self._do_balance_migrate(candidate, target)
            if ok:
                migrated += 1
                time.sleep(5)  # brief pause between migrations
                # re-check balance after each migration
                needs, max_node, min_node = self.check_balance_needed()
                if not needs:
                    break

        if migrated:
            self.logger.info(f"[BALANCE] cycle done, {migrated} VM(s) migrated")

    # ──────────────────────────────────────────
    # Predictive analysis - MK Mar 2026
    # ──────────────────────────────────────────

    def _compute_predictive_score(self, node_name, window=24):
        """Weighted moving average over recent metrics. Returns forecast dict.

        window: hours of history to consider (capped by available data).
        """
        hist = self._node_metrics_history.get(node_name, [])
        if not hist:
            return None

        now = time.time()
        cutoff = now - (window * 3600)
        recent = [s for s in hist if s['ts'] >= cutoff]
        if len(recent) < 3:
            recent = hist[-10:]  # not enough data, use what we have

        n = len(recent)
        # exponential weights - newer samples weigh more
        total_w = 0
        cpu_weighted = 0
        mem_weighted = 0
        for i, s in enumerate(recent):
            w = (i + 1) ** 1.5  # slightly super-linear weight
            cpu_weighted += s['cpu'] * w
            mem_weighted += s['mem'] * w
            total_w += w

        avg_cpu = cpu_weighted / total_w if total_w else 0
        avg_mem = mem_weighted / total_w if total_w else 0

        # trend = difference between first and last third averages
        third = max(1, n // 3)
        early_cpu = sum(s['cpu'] for s in recent[:third]) / third
        late_cpu = sum(s['cpu'] for s in recent[-third:]) / third
        early_mem = sum(s['mem'] for s in recent[:third]) / third
        late_mem = sum(s['mem'] for s in recent[-third:]) / third

        cpu_trend = late_cpu - early_cpu
        mem_trend = late_mem - early_mem

        # confidence based on data density
        expected_samples = window * 3600 / 15  # one sample per 15s
        confidence = min(1.0, n / max(expected_samples * 0.3, 1))

        return {
            'score': round(avg_cpu + avg_mem, 1),
            'trend': 'rising' if (cpu_trend + mem_trend) > 5 else ('falling' if (cpu_trend + mem_trend) < -5 else 'stable'),
            'confidence': round(confidence, 2),
            'cpu_forecast': round(avg_cpu + cpu_trend * 0.5, 1),
            'mem_forecast': round(avg_mem + mem_trend * 0.5, 1),
            'cpu_trend': round(cpu_trend, 1),
            'mem_trend': round(mem_trend, 1),
            'samples': n,
        }

    def get_predictive_analysis(self):
        """Predictive analysis for all nodes. Called via api/reports.py dispatch."""
        nodes = self._cached_nodes or self.get_nodes() or []
        results = {}
        for n in nodes:
            name = n.get('node', '')
            pred = self._compute_predictive_score(name)
            if pred:
                results[name] = pred
        return results

    def get_last_migration_log(self):
        return self.last_migration_log

    # scheduler compat
    def restart_vm(self, node, vmid, vm_type='qemu'):
        return self.reboot_vm(node, vmid)

    def backup_vm(self, node, vmid, vm_type='qemu', **kwargs):
        # NS: XCP-ng backups are done via Xen Orchestra, not built-in
        self.logger.warning(f"backup_vm called for {vmid} but XCP-ng backup not supported via PegaProx")
        return None

    # alerts compat
    def get_cluster_summary(self):
        return self.get_cluster_status()

    def get_resources(self):
        """Return resources in Proxmox /cluster/resources format."""
        vms = self.get_vms() or []
        nodes = self.get_nodes() or []
        resources = []
        for n in nodes:
            resources.append({**n, 'type': 'node', 'id': f"node/{n.get('node', '')}"})
        for v in vms:
            resources.append({**v, 'id': f"qemu/{v.get('vmid', '')}"})
        return resources

    # API token stubs (XAPI uses sessions, not tokens)
    def create_api_token(self, token_name=''):
        return None

    def delete_api_token(self, token_name=''):
        pass

    def get_cluster_fingerprint(self):
        return None

    # container compat (XCP-ng has no LXC)
    def create_container(self, node, config):
        return {'success': False, 'error': 'LXC containers not supported on XCP-ng'}

    @property
    def nodes(self):
        """Node dict keyed by hostname - needed by metrics collector + search."""
        cached = self._cached_nodes
        if not cached:
            return {}
        return {n['node']: n for n in cached}

    @staticmethod
    def _bracket_ipv6(h):
        if h and ':' in h and not h.startswith('['):
            return f'[{h}]'
        return h

    @property
    def host(self):
        """Host for URL construction - brackets IPv6 (#145)"""
        h = self.current_host or self.config.host
        return self._bracket_ipv6(h)

    @property
    def raw_host(self):
        return self.current_host or self.config.host
