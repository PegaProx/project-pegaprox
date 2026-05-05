# -*- coding: utf-8 -*-
"""
Sylve host manager - beta integration layer.

Keeps the same broad public surface as the XCP-ng/Proxmox managers for the
parts of the UI we currently support: cluster card status, node list, VM/jail
listing, node summary, network view, and basic historical charts.
"""

import logging
import socket
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from pegaprox.constants import LOG_DIR


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class SylveManager:
    """Sylve manager with a PegaProx/XCP-ng compatible read-focused surface."""

    def __init__(self, cluster_id: str, config):
        self.id = cluster_id
        self.config = config
        self.cluster_type = 'sylve'
        self.host = config.host
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()
        self.last_run = None

        self.is_connected = False
        self.current_host = None
        self.connection_error = None

        self._session = requests.Session()
        self._session.verify = bool(getattr(config, 'ssl_verification', False))
        self._session_lock = threading.Lock()
        self._token = ''
        self._base_url = ''

        self._cached_node = None
        self._cached_vms = []
        self._cached_storages = []
        self._cache_time = 0
        self._cache_ttl = 15

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

        self.logger = logging.getLogger(f"Sylve_{config.name}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        if self.logger.handlers:
            self.logger.handlers.clear()
        fh = logging.FileHandler(f"{LOG_DIR}/{cluster_id}.log")
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        fmt = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s')
        fh.setFormatter(fmt)
        ch.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def _candidate_base_urls(self) -> List[str]:
        host = (self.config.host or '').strip().rstrip('/')
        if not host:
            return []
        if host.startswith('http://') or host.startswith('https://'):
            return [host]
        return [f"https://{host}", f"http://{host}"]

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token:
            return {}
        return {'Authorization': f'Bearer {self._token}'}

    def _extract_data(self, payload: Any) -> Any:
        if isinstance(payload, dict) and 'data' in payload and (
            payload.get('status') is not None or payload.get('message') is not None or payload.get('error') is not None
        ):
            return payload.get('data')
        return payload

    def _request(self, method: str, path: str, *, retry: bool = True, **kwargs):
        if not self._base_url:
            raise ConnectionError('Sylve base URL is not initialized')

        url = f"{self._base_url}/api{path}"
        headers = kwargs.pop('headers', {})
        headers = {**self._auth_headers(), **headers}
        resp = self._session.request(method, url, headers=headers, timeout=kwargs.pop('timeout', 15), **kwargs)

        if resp.status_code == 401 and retry and self.connect():
            return self._request(method, path, retry=False, **kwargs)

        resp.raise_for_status()
        if not resp.content:
            return None
        return resp.json()

    def connect(self) -> bool:
        with self._session_lock:
            username = self.config.user
            password = self.config.pass_
            last_error = 'No usable Sylve endpoint found'

            for base_url in self._candidate_base_urls():
                try:
                    resp = self._session.post(
                        f"{base_url}/api/auth/login",
                        json={'username': username, 'password': password},
                        timeout=15,
                    )
                    resp.raise_for_status()
                    data = resp.json() or {}
                    token = data.get('token') or data.get('data', {}).get('token')
                    if not token:
                        raise ValueError('Sylve login succeeded but no JWT token was returned')

                    self._token = token
                    self._base_url = base_url
                    self.current_host = base_url
                    self.is_connected = True
                    self.connection_error = None
                    self.logger.info(f"Connected to Sylve host: {base_url}")
                    return True
                except Exception as e:
                    last_error = str(e)
                    self.logger.debug(f"Sylve login attempt failed for {base_url}: {e}")

            self._token = ''
            self._base_url = ''
            self.is_connected = False
            self.connection_error = last_error
            self.logger.error(f"Sylve connect failed: {last_error}")
            return False

    def connect_to_proxmox(self) -> bool:
        return self.connect()

    def disconnect(self):
        with self._session_lock:
            self._token = ''
            self.is_connected = False
            self.logger.info("Disconnected from Sylve")

    def test_connection(self) -> bool:
        return self.connect()

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name=f"sylve-{self.id}")
        self.thread.start()
        self.logger.info("Sylve manager started")

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.disconnect()
        self.logger.info("Sylve manager stopped")

    def _run_loop(self):
        self.connect()
        while not self.stop_event.is_set():
            try:
                if not self.is_connected and not self.connect():
                    time.sleep(30)
                    continue
                self._refresh_cache(force=True)
                self.last_run = datetime.now()
            except Exception as e:
                self.connection_error = str(e)
                self.is_connected = False
                self.logger.error(f"Sylve refresh loop failed: {e}")
            time.sleep(max(15, int(getattr(self.config, 'check_interval', 300) or 300)))

    def _refresh_cache(self, force: bool = False):
        now = time.time()
        if not force and self._cached_node is not None and now - self._cache_time < self._cache_ttl:
            return

        basic = self._extract_data(self._request('GET', '/info/basic')) or {}
        cpu = self._extract_data(self._request('GET', '/info/cpu')) or {}
        ram = self._extract_data(self._request('GET', '/info/ram')) or {}
        swap = self._extract_data(self._request('GET', '/info/swap')) or {}
        pools = self._extract_data(self._request('GET', '/zfs/pools')) or []
        vms = self._extract_data(self._request('GET', '/vm')) or []
        jails = self._extract_data(self._request('GET', '/jail')) or []

        hostname = basic.get('hostname') or self.config.name or self.config.host
        cpu_usage_pct = _to_float(cpu.get('usage'))
        total_mem = _to_int(ram.get('total'))
        free_mem = _to_int(ram.get('free'))
        used_mem = max(0, total_mem - free_mem)

        total_storage = 0
        used_storage = 0
        storages = []
        for pool in pools:
            size = _to_int(pool.get('size'))
            allocated = _to_int(pool.get('allocated'))
            total_storage += size
            used_storage += allocated
            storages.append({
                'storage': pool.get('name', ''),
                'type': 'zpool',
                'total': size,
                'used': allocated,
                'avail': max(0, size - allocated),
                'status': str(pool.get('state', 'ONLINE')).lower(),
                'shared': False,
                'content': 'images,rootdir',
                'uuid': pool.get('pool_guid', ''),
            })

        node = {
            'node': hostname,
            'status': 'online',
            'id': hostname,
            'cpu': cpu_usage_pct / 100.0 if cpu_usage_pct > 1 else cpu_usage_pct,
            'maxcpu': _to_int(cpu.get('logicalCores')) or _to_int(cpu.get('physicalCores')) or 1,
            'mem': used_mem,
            'maxmem': total_mem,
            'uptime': _to_int(basic.get('uptime')),
            'netin': 0,
            'netout': 0,
            'type': 'node',
            '_loadavg': [x.strip() for x in str(basic.get('loadAverage', '')).split(',') if x.strip()],
            '_cpuinfo': cpu,
            '_basic': basic,
            '_ram': ram,
            '_swap': swap,
            '_storage_total': total_storage,
            '_storage_used': used_storage,
        }

        mapped_vms = []
        for vm in vms:
            rid = vm.get('rid') if vm.get('rid') is not None else vm.get('id')
            state = vm.get('state')
            status = 'running' if str(state) in ('1', 'running', 'Running') else 'stopped'
            mapped_vms.append({
                'vmid': _to_int(rid),
                'name': vm.get('name', f'vm-{rid}'),
                'node': hostname,
                'type': 'qemu',
                'status': status,
                'cpu': 0,
                'maxcpu': _to_int(vm.get('cpuSockets', 1)) * _to_int(vm.get('cpuCores', 1)) * max(1, _to_int(vm.get('cpuThreads', 1))),
                'mem': 0,
                'maxmem': _to_int(vm.get('ram')),
            })

        for jail in jails:
            ctid = jail.get('ctId') if jail.get('ctId') is not None else jail.get('id')
            mapped_vms.append({
                'vmid': _to_int(ctid),
                'name': jail.get('name', f'jail-{ctid}'),
                'node': hostname,
                'type': 'lxc',
                'status': 'running' if str(jail.get('startedAt') or '').strip() else 'stopped',
                'cpu': 0,
                'maxcpu': _to_int(jail.get('cores', 1)) or 1,
                'mem': 0,
                'maxmem': _to_int(jail.get('memory')),
            })

        self._cached_node = node
        self._cached_vms = mapped_vms
        self._cached_storages = storages
        self._cache_time = now
        self.is_connected = True
        self.connection_error = None

    def _ensure_cache(self):
        if self._cached_node is None or (time.time() - self._cache_time) > self._cache_ttl:
            self._refresh_cache()

    def _node_name(self) -> str:
        self._ensure_cache()
        return (self._cached_node or {}).get('node', self.config.name or self.config.host)

    def _host_from_config(self) -> str:
        parsed = urlparse(self._base_url or '')
        if parsed.hostname:
            return parsed.hostname
        raw = (self.config.host or '').strip()
        if raw.startswith('http://') or raw.startswith('https://'):
            return urlparse(raw).hostname or raw
        if ':' in raw:
            return raw.split(':', 1)[0]
        return raw

    def _get_host_ip(self, node_name: str):
        try:
            return socket.gethostbyname(self._host_from_config())
        except Exception:
            return self._host_from_config()

    def get_nodes(self) -> list:
        self._ensure_cache()
        node = self._cached_node or {}
        return [{k: v for k, v in node.items() if not k.startswith('_')}]

    def get_vms(self, node=None) -> list:
        self._ensure_cache()
        vms = list(self._cached_vms or [])
        if node:
            vms = [vm for vm in vms if vm.get('node') == node]
        return vms

    def get_storages(self, node=None) -> list:
        self._ensure_cache()
        return list(self._cached_storages or [])

    def get_cluster_status(self) -> dict:
        self._ensure_cache()
        node = self._cached_node or {}
        vms = self._cached_vms or []
        return {
            'nodes': 1,
            'vms': len([v for v in vms if v.get('type') == 'qemu']),
            'jails': len([v for v in vms if v.get('type') == 'lxc']),
            'running_vms': len([v for v in vms if v.get('type') == 'qemu' and v.get('status') == 'running']),
            'running_jails': len([v for v in vms if v.get('type') == 'lxc' and v.get('status') == 'running']),
            'total_cpu': node.get('maxcpu', 0),
            'total_mem': node.get('maxmem', 0),
            'used_mem': node.get('mem', 0),
            'cluster_type': 'sylve',
        }

    def get_node_status(self) -> dict:
        self._ensure_cache()
        node = self._cached_node or {}
        maxmem = node.get('maxmem', 0)
        mem_used = node.get('mem', 0)
        cpu_pct = round((node.get('cpu', 0) or 0) * 100, 1)
        mem_pct = round(mem_used / maxmem * 100, 1) if maxmem else 0
        name = node.get('node', self.config.name)
        return {
            name: {
                'status': node.get('status', 'unknown'),
                'cpu_percent': cpu_pct,
                'mem_used': mem_used,
                'mem_total': maxmem,
                'mem_percent': mem_pct,
                'disk_used': node.get('_storage_used'),
                'disk_total': node.get('_storage_total'),
                'disk_percent': round(node.get('_storage_used', 0) / node.get('_storage_total', 1) * 100, 1) if node.get('_storage_total') else None,
                'netin': node.get('netin', 0),
                'netout': node.get('netout', 0),
                'uptime': node.get('uptime', 0),
                'score': cpu_pct + mem_pct,
                'loadavg': node.get('_loadavg'),
                'cpuinfo': {
                    'cores': _to_int(node.get('_cpuinfo', {}).get('physicalCores')),
                    'sockets': _to_int(node.get('_cpuinfo', {}).get('sockets')),
                },
                'pveversion': f"Sylve {node.get('_basic', {}).get('sylveVersion', '')}".strip(),
                'maintenance_mode': False,
                'offline': False,
            }
        }

    def get_vm_resources(self) -> list:
        return self.get_nodes() + self.get_vms()

    def get_node_summary(self, node):
        self._ensure_cache()
        cnode = self._cached_node or {}
        cpuinfo = cnode.get('_cpuinfo', {})
        basic = cnode.get('_basic', {})
        ram = cnode.get('_ram', {})
        swap = cnode.get('_swap', {})
        return {
            'status': cnode.get('status', 'unknown'),
            'uptime': cnode.get('uptime', 0),
            'cpu': cnode.get('cpu', 0),
            'loadavg': cnode.get('_loadavg', []),
            'memory': {
                'used': cnode.get('mem', 0),
                'total': cnode.get('maxmem', 0),
            },
            'swap': {
                'used': max(0, _to_int(swap.get('total')) - _to_int(swap.get('free'))),
                'total': _to_int(swap.get('total')),
            },
            'rootfs': {
                'used': cnode.get('_storage_used', 0),
                'total': cnode.get('_storage_total', 0),
            },
            'kversion': basic.get('os', ''),
            'pveversion': f"Sylve {basic.get('sylveVersion', '')}".strip(),
            'cpuinfo': {
                'model': cpuinfo.get('name', ''),
                'cores': _to_int(cpuinfo.get('physicalCores')),
                'cpus': _to_int(cpuinfo.get('logicalCores')),
                'sockets': _to_int(cpuinfo.get('sockets')),
            },
        }

    def get_node_network_config(self, node):
        payload = self._extract_data(self._request('GET', '/network/interface')) or []
        interfaces = []
        for iface in payload:
            ipv4 = iface.get('ipv4') or []
            first_ipv4 = ipv4[0] if ipv4 else {}
            ip_arr = first_ipv4.get('ip') or []
            address = '.'.join(str(x) for x in ip_arr) if ip_arr else ''
            interfaces.append({
                'iface': iface.get('name', ''),
                'type': 'bridge' if iface.get('bridgeMembers') else 'eth',
                'active': 'UP' in (iface.get('flags', {}) or {}).get('desc', []),
                'address': address,
                'netmask': first_ipv4.get('netmask', ''),
                'gateway': '',
                'cidr': f"{address}/{first_ipv4.get('netmask', '')}" if address and first_ipv4.get('netmask') else address,
                'bridge': iface.get('bridgeId', ''),
                'network': iface.get('description', ''),
                'method': 'static' if address else 'manual',
                'families': ['inet'] if address else [],
                'autostart': True,
                'mac': iface.get('ether') or iface.get('hwaddr', ''),
                'mtu': _to_int(iface.get('mtu'), 1500),
                'comments': iface.get('description', ''),
                'driver': iface.get('driver', ''),
            })
        return interfaces

    def get_node_rrddata(self, node: str, timeframe: str = 'hour'):
        cpu_hist = self._extract_data(self._request('GET', '/info/cpu/historical')) or []
        ram_hist = self._extract_data(self._request('GET', '/info/ram/historical')) or []
        swap_hist = self._extract_data(self._request('GET', '/info/swap/historical')) or []
        net_hist = self._extract_data(self._request('GET', '/info/network-interfaces/historical')) or []

        timestamps = []
        cpu_map = {}
        ram_map = {}
        swap_map = {}
        net_in_map = {}
        net_out_map = {}

        def _remember(series, target, key):
            for item in series:
                ts_raw = item.get(key)
                if not ts_raw:
                    continue
                try:
                    ts = int(datetime.fromisoformat(str(ts_raw).replace('Z', '+00:00')).timestamp())
                except Exception:
                    continue
                target[ts] = item
                timestamps.append(ts)

        _remember(cpu_hist, cpu_map, 'createdAt')
        _remember(ram_hist, ram_map, 'createdAt')
        _remember(swap_hist, swap_map, 'createdAt')
        _remember(net_hist, net_in_map, 'createdAt')
        _remember(net_hist, net_out_map, 'createdAt')

        ordered = sorted(set(timestamps))
        return {
            'timeframe': timeframe,
            'node': node,
            'metrics': {
                'cpu': [round(_to_float(cpu_map.get(ts, {}).get('usage')), 2) for ts in ordered],
                'memory': [round(_to_float(ram_map.get(ts, {}).get('usage')), 2) for ts in ordered],
                'swap': [round(_to_float(swap_map.get(ts, {}).get('usage')), 2) for ts in ordered],
                'iowait': [0 for _ in ordered],
                'loadavg': [0 for _ in ordered],
                'net_in': [_to_int(net_in_map.get(ts, {}).get('receivedBytes')) for ts in ordered],
                'net_out': [_to_int(net_out_map.get(ts, {}).get('sentBytes')) for ts in ordered],
                'rootfs': [0 for _ in ordered],
            },
            'timestamps': ordered,
        }
