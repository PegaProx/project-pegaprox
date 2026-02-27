# -*- coding: utf-8 -*-
"""
PegaProx Cluster Manager - Layer 5
Main cluster management: Proxmox API, load balancing, HA.
"""

import os
import sys
import json
import time
import logging
import threading
import uuid
import socket
import hashlib
import subprocess
import re
import shlex
import requests
import urllib3
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any, Dict, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pegaprox.constants import SSH_MAX_CONCURRENT, LOG_DIR
from pegaprox import globals as _g
from pegaprox.globals import (
    cluster_managers, _ssh_active_connections,
    _ssh_connection_lock, task_pegaprox_users_cache, task_pegaprox_users_lock,
)
from pegaprox.models.tasks import MaintenanceTask, PegaProxConfig
from pegaprox.core.config import save_config
from pegaprox.utils.realtime import broadcast_sse
from pegaprox.utils.ssh import get_ssh_connection_stats, _ssh_track_connection
from pegaprox.utils.concurrent import GEVENT_PATCHED
from pegaprox.core.db import get_db

# Lazy paramiko import
def get_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None

# Gevent pool
GEVENT_AVAILABLE = False
GEVENT_POOL = None
try:
    from gevent.pool import Pool as GeventPool
    # NS: pool size 50 because 100 caused fd exhaustion on the Hetzner box (ulimit was 1024)
    GEVENT_POOL = GeventPool(size=50)
    GEVENT_AVAILABLE = True
except ImportError:
    pass

def run_concurrent(tasks: list, timeout: float = 30.0) -> list:
    if not tasks:
        return []
    if GEVENT_POOL and GEVENT_AVAILABLE:
        try:
            greenlets = [GEVENT_POOL.spawn(task) for task in tasks]
            from gevent import joinall
            joinall(greenlets, timeout=timeout)
            results = []
            for g in greenlets:
                try:
                    results.append(g.value if g.successful() else None)
                except Exception as e:
                    logging.error(f"Concurrent task failed: {e}")
                    results.append(None)
            return results
        except Exception as e:
            logging.error(f"Concurrent execution failed: {e}")
    results = []
    for task in tasks:
        try:
            results.append(task())
        except Exception as e:
            logging.error(f"Task failed: {e}")
            results.append(None)
    return results

def run_concurrent_dict(tasks: dict, timeout: float = 30.0) -> dict:
    if not tasks:
        return {}
    keys = list(tasks.keys())
    callables = [tasks[k] for k in keys]
    results = run_concurrent(callables, timeout)
    return dict(zip(keys, results))

class UpdateTask:
    
    def __init__(self, node: str, reboot: bool = True):
        self.node = node
        self.reboot = reboot
        self.started_at = datetime.now()
        self.status = 'starting'  # starting, updating, rebooting, waiting_online, completed, failed
        self.phase = 'init'  # init, apt_update, apt_upgrade, reboot, wait_online
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

class PegaProxManager:
    """
    main cluster manager - NS

    handles all the proxmox api stuff, loadbalancing, HA etc
    each cluster runs in its own thread

    this class is kinda big, should probably split it up someday - MK
    """

    # MK: lock reason descriptions for UI display
    LOCK_DESCRIPTIONS = {
        'migrate': 'Migration in progress',
        'backup': 'Backup in progress',
        'snapshot': 'Snapshot operation in progress',
        'rollback': 'Snapshot rollback in progress',
        'clone': 'Clone operation in progress',
        'create': 'VM creation in progress',
        'disk': 'Disk operation in progress',
        'suspended': 'VM suspended to disk',
        'suspending': 'VM is being suspended',
        'copy': 'Copy operation in progress',
    }

    def __init__(self, cluster_id: str, config: PegaProxConfig):
        self.id = cluster_id
        self.config = config
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()
        self.last_run = None
        self.last_migration_log = []
        
        # maintenance mode
        self.nodes_in_maintenance = {}
        self._cached_node_dict = {}
        self._nodes_cache_time = 0
        # cache ttl is 8 seconds, not 10 - api returns stale data for up to 6s after a migration
        # and we need the 2s buffer on top so the ui never shows the vm on the old node
        self._nodes_cache_ttl = 8
        self.maintenance_lock = threading.Lock()
        
        # update tracking
        self.nodes_updating = {}
        self.update_lock = threading.Lock()
        
        # HA stuff - MK added this
        self.ha_enabled = getattr(config, 'ha_enabled', False)
        self.ha_check_interval = 10
        self.ha_thread = None
        self.ha_node_status = {}  # node -> status dict
        self.ha_lock = threading.Lock()
        self.ha_recovery_in_progress = {}
        
        # load saved HA settings
        saved_ha = getattr(config, 'ha_settings', {}) or {}
        
        self.ha_failure_threshold = saved_ha.get('failure_threshold', 3)
        
        # split-brain stuff (complicated, dont touch) - NS
        self.ha_config = {
            'quorum_enabled': saved_ha.get('quorum_enabled', True),
            'quorum_hosts': saved_ha.get('quorum_hosts', []),
            'quorum_gateway': saved_ha.get('quorum_gateway', ''),
            'quorum_required_votes': saved_ha.get('quorum_required_votes', 2),
            
            # self-fencing
            'self_fence_enabled': saved_ha.get('self_fence_enabled', True),
            'watchdog_enabled': saved_ha.get('watchdog_enabled', False),
            
            # network checks
            'verify_network_before_recovery': saved_ha.get('verify_network', True),
            'network_check_hosts': saved_ha.get('network_check_hosts', []),
            'network_check_required': saved_ha.get('network_check_required', 1),
            
            # storage fencing
            'storage_fence_enabled': saved_ha.get('storage_fence_enabled', False),
            
            # storage heartbeat - safest for 2-node clusters
            # NS: spent forever getting this to work right
            'storage_heartbeat_enabled': saved_ha.get('storage_heartbeat_enabled', False),
            'storage_heartbeat_path': saved_ha.get('storage_heartbeat_path', ''),
            'storage_heartbeat_interval': saved_ha.get('storage_heartbeat_interval', 5),
            'storage_heartbeat_timeout': saved_ha.get('storage_heartbeat_timeout', 30),
            'poison_pill_enabled': saved_ha.get('poison_pill_enabled', True),
            
            # ═══════════════════════════════════════════════════════════════
            # DUAL-NETWORK PROTECTION - NS Jan 2026
            # For setups with separate Server and Storage networks!
            # Auto-installs a small agent on each node that communicates
            # via the storage network (survives server network failures)
            # ═══════════════════════════════════════════════════════════════
            'dual_network_mode': saved_ha.get('dual_network_mode', False),
            'node_agent_installed': saved_ha.get('node_agent_installed', {}),  # node -> True/False
            'self_fence_installed': saved_ha.get('self_fence_installed', False),  # MK: was missing, status got lost on restart
            'self_fence_nodes': saved_ha.get('self_fence_nodes', []),  # NS: list of nodes with agent installed
            
            # Timing - defaults tuned for 3-node ceph setups (most common in the field)
            # for 2-node with shared storage, recovery_delay should be higher (45-60)
            # because the surviving node needs time to import the pool locks
            'recovery_delay': saved_ha.get('recovery_delay', 30),  # seconds before recovery starts
            'node_timeout': saved_ha.get('node_timeout', 60),  # node must be dead this long
            'ssh_connect_timeout': saved_ha.get('ssh_connect_timeout', 10),  # ssh timeout per node
            
            # ═══════════════════════════════════════════════════════════════
            # 2-NODE CLUSTER MODE - Automatic quorum handling
            # Uses cluster credentials (same as Proxmox API login) for SSH
            # ═══════════════════════════════════════════════════════════════
            'two_node_mode': saved_ha.get('two_node_mode', False),
            'force_quorum_on_failure': saved_ha.get('force_quorum_on_failure', False),
            
            # ═══════════════════════════════════════════════════════════════
            # STRICT MODE - Maximum safety, may cause false positives
            # ═══════════════════════════════════════════════════════════════
            'strict_fencing': saved_ha.get('strict_fencing', False),  # Require successful fencing before recovery
            'require_storage_heartbeat_confirm': saved_ha.get('require_storage_heartbeat_confirm', False),  # Must confirm via storage
            
            # Node IPs (auto-discovered but can be overridden)
            'node_ips': saved_ha.get('node_ips', {}),  # node_name -> ip
        }
        
        # Storage heartbeat tracking
        self.ha_heartbeat_thread = None
        self.ha_heartbeat_stop = threading.Event()
        self.ha_last_heartbeat_write = None
        
        # Quorum tracking - NS Jan 2026
        self.ha_have_quorum = True  # Assume quorum until proven otherwise
        self.ha_last_quorum_check = None
        
        # Setup logging
        self.logger = logging.getLogger(f"PegaProx_{config.name}")
        self.logger.setLevel(logging.DEBUG)  # File gets everything
        self.logger.propagate = False  # MK: Don't propagate to root logger (prevents DEBUG spam)
        
        # Clear existing handlers to prevent duplicates - NS Jan 2026
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # File handler - DEBUG level (for troubleshooting)
        fh = logging.FileHandler(f"{LOG_DIR}/{cluster_id}.log")
        fh.setLevel(logging.DEBUG)
        
        # Console handler - INFO level (no DEBUG spam)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        # Proxmox API credentials (stored, not session)
        self._ticket = None
        self._csrf_token = None
        self._api_token = None  # NS: for API token auth (user@realm!tokenid=secret)
        self._using_api_token = False
        self.current_host = None  # Track which host we're connected to
        self._ssl_verify = False
        
        # Connection state tracking
        self.is_connected = False
        self.last_successful_request = None
        self.connection_error = None
        self._consecutive_failures = 0  # NS: track failed requests for smarter disconnect detection
        self._disabled_check_counter = 0  # LW: for checking connection even when disabled
        self._last_reconnect_attempt = 0  # NS: Feb 2026 - throttle reconnection attempts in broadcast loop
        self._consecutive_empty_responses = 0  # NS: Feb 2026 - detect stale tickets (connected but empty data)
        
        # Default timeout for API requests
        self.api_timeout = 10
        
        # Lock for connection operations
        self._connect_lock = threading.Lock()
    
    def _create_session(self):
        """
        Create a new requests session with auth - thread safe
        
        MK: Each request gets a fresh session to avoid threading issues
        Tried session pooling but gevent + requests was causing deadlocks
        
        NS: Added API token support Jan 2026 (GitHub Issue #5)
        Token auth uses Authorization header, password auth uses cookies
        """
        session = requests.Session()
        session.verify = self._ssl_verify
        
        if getattr(self, '_api_token', None):
            # API Token auth - use Authorization header
            session.headers.update({'Authorization': f'PVEAPIToken={self._api_token}'})
        else:
            # Password auth - use ticket cookie
            if self._ticket:
                session.cookies.set('PVEAuthCookie', self._ticket)
            if self._csrf_token:
                session.headers.update({'CSRFPreventionToken': self._csrf_token})
        return session
    
    @property
    def host(self) -> str:
        return self.current_host or self.config.host
    
    @property
    def nodes(self) -> dict:
        """Return cached node status dict (node_name -> info). Lazy-populated with 30s TTL."""
        now = time.time()
        if self._cached_node_dict and hasattr(self, '_nodes_cache_time') and (now - self._nodes_cache_time) < 30:
            return self._cached_node_dict
        if not self.is_connected or not self.session:
            return self._cached_node_dict or {}
        try:
            url = f"https://{self.host}:8006/api2/json/nodes"
            resp = self._api_get(url)
            if resp.status_code == 200:
                self._cached_node_dict = {n['node']: n for n in resp.json().get('data', [])}
                self._nodes_cache_time = now
                return self._cached_node_dict
        except:
            pass
        return self._cached_node_dict or {}
    
    @property
    def ticket(self) -> str:
        return self._ticket
    
    # LW: All API methods go through these wrappers for consistent error handling
    # MK: Jan 2026 - Fixed timeout handling, was marking cluster offline too eagerly
    def _api_get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.api_timeout)
        try:
            session = self._create_session()
            response = session.get(url, **kwargs)
            # Track connection state for UI
            self.is_connected = True
            self.last_successful_request = datetime.now()
            self.connection_error = None
            self._consecutive_failures = 0  # reset failure counter on success
            return response
        except requests.exceptions.Timeout as e:
            # MK: Timeout != offline. Proxmox might just be slow (happens a lot with ZFS)
            self.connection_error = f"Request timed out: {e}"
            raise
        except requests.exceptions.ConnectionError as e:
            # LW: Only mark disconnected after 3 consecutive failures to avoid flapping
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3:
                self.is_connected = False
                self.connection_error = str(e)
            raise
    
    def _api_post(self, url, **kwargs):
        kwargs.setdefault('timeout', self.api_timeout)
        try:
            sess = self._create_session()
            resp = sess.post(url, **kwargs)
            self.is_connected = True
            self.last_successful_request = datetime.now()
            self.connection_error = None
            self._consecutive_failures = 0
            return resp
        except requests.exceptions.Timeout as e:
            # MK: Timeout does NOT mean cluster is offline
            self.connection_error = f"Request timed out: {e}"
            raise
        except requests.exceptions.ConnectionError as e:
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3:
                self.is_connected = False
                self.connection_error = str(e)
            raise
    
    def _api_put(self, url, **kwargs):
        kwargs.setdefault('timeout', self.api_timeout)
        try:
            session = self._create_session()
            response = session.put(url, **kwargs)
            self.is_connected = True
            self.last_successful_request = datetime.now()
            self.connection_error = None
            self._consecutive_failures = 0
            return response
        except requests.exceptions.Timeout as e:
            # MK: Timeout does NOT mean cluster is offline - operation might have succeeded
            self.connection_error = f"Request timed out: {e}"
            self.logger.warning(f"[WARN] API PUT timeout (not marking offline): {e}")
            raise
        except requests.exceptions.ConnectionError as e:
            # Real connection error - only mark offline after multiple failures
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3:
                self.is_connected = False
                self.connection_error = str(e)
            raise
    
    def _api_delete(self, url, **kwargs):
        # same as put but delete
        kwargs.setdefault('timeout', self.api_timeout)
        try:
            session = self._create_session()
            r = session.delete(url, **kwargs)
            self.is_connected = True
            self.last_successful_request = datetime.now()
            self.connection_error = None
            self._consecutive_failures = 0
            return r
        except requests.exceptions.Timeout as e:
            # MK: Timeout does NOT mean cluster is offline
            self.connection_error = f"Request timed out: {e}"
            self.logger.warning(f"[WARN] API DELETE timeout (not marking offline): {e}")
            raise
        except requests.exceptions.ConnectionError as e:
            # Real connection error - only mark offline after multiple failures
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3:
                self.is_connected = False
                self.connection_error = str(e)
            raise
    
    def api_request(self, method: str, endpoint: str, data: dict = None):
        """generic api request wrapper - NS Jan 2026"""
        host = self.current_host or self.config.host
        url = f'https://{host}:8006/api2/json{endpoint}'
        
        try:
            if method.upper() == 'GET':
                r = self._api_get(url, verify=self._ssl_verify)
            elif method.upper() == 'POST':
                r = self._api_post(url, json=data, verify=self._ssl_verify)
            elif method.upper() == 'PUT':
                r = self._api_put(url, json=data, verify=self._ssl_verify)
            elif method.upper() == 'DELETE':
                r = self._api_delete(url, verify=self._ssl_verify)
            else:
                self.logger.error(f"Unknown HTTP method: {method}")
                return None
            
            if r.status_code == 200:
                return r.json().get('data')
            else:
                self.logger.warning(f"API request failed: {method} {endpoint} -> {r.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"API request error: {method} {endpoint} -> {e}")
            return None
        
    def connect_to_proxmox(self) -> bool:
        # connect with fallback
        with self._connect_lock:
            # Build list of hosts to try: primary first, then fallbacks
            hosts_to_try = [self.config.host] + (self.config.fallback_hosts or [])
            
            self._ssl_verify = self.config.ssl_verification
            # self._ssl_verify = False  # tmp disable for debugging cert issues
            
            # NS: Check if using API Token (format: user@realm!tokenid)
            # API tokens have ! in the username, passwords don't
            self._using_api_token = '!' in self.config.user
            
            for host in hosts_to_try:
                try:
                    # Create a temporary session just for login
                    session = requests.Session()
                    session.verify = self._ssl_verify
                    
                    if self._using_api_token:
                        # API Token auth - no ticket needed!
                        # Token goes in Authorization header: PVEAPIToken=user@realm!tokenid=secret
                        self._api_token = f"{self.config.user}={self.config.pass_}"
                        self._ticket = None
                        self._csrf_token = None
                        
                        # Test the token by making a simple API call
                        test_url = f"https://{host}:8006/api2/json/version"
                        headers = {'Authorization': f'PVEAPIToken={self._api_token}'}
                        resp = session.get(test_url, headers=headers, timeout=10)
                        
                        if resp.status_code == 200:
                            self.current_host = host
                            # Invalidate mgmt interface cache on host change
                            if hasattr(self, "_cached_mgmt_iface"):
                                self._cached_mgmt_iface = None
                                self._cached_mgmt_network = None
                                self._cached_mgmt_vlan = None
                            self.is_connected = True
                            self.last_successful_request = datetime.now()
                            self.connection_error = None
                            self.session = True
                            
                            self.logger.info(f"Connected to Proxmox at {host} using API Token")
                            
                            if not self.config.fallback_hosts:
                                self._auto_discover_fallback_hosts()
                            
                            return True
                        else:
                            self.logger.warning(f"API Token auth failed at {host}: {resp.status_code}")
                    else:
                        # Password auth - get ticket from /access/ticket
                        login_data = {
                            'username': self.config.user,
                            'password': self.config.pass_
                        }
                        # print(f"DEBUG: trying {host}")  # dont commit this
                        
                        login_url = f"https://{host}:8006/api2/json/access/ticket"
                        resp = session.post(login_url, data=login_data, timeout=10)
                        
                        if resp.status_code == 200:
                            data = resp.json()['data']
                            self._ticket = data['ticket']
                            self._csrf_token = data['CSRFPreventionToken']
                            self._api_token = None
                            
                            self.current_host = host
                            # Invalidate mgmt interface cache on host change
                            if hasattr(self, "_cached_mgmt_iface"):
                                self._cached_mgmt_iface = None
                                self._cached_mgmt_network = None
                                self._cached_mgmt_vlan = None
                            self.is_connected = True
                            self.last_successful_request = datetime.now()
                            self.connection_error = None
                            
                            # For backward compatibility - some code still checks self.session
                            # NS: this is ugly but works, passt eh
                            self.session = True  # Just a truthy value
                            
                            if host != self.config.host:
                                self.logger.warning(f"Connected to FALLBACK host {host} (primary {self.config.host} unavailable)")
                            else:
                                self.logger.info(f"Successfully connected to Proxmox at {host}")
                            
                            # Auto-discover fallback hosts if not already set
                            if not self.config.fallback_hosts:
                                self._auto_discover_fallback_hosts()
                            
                            return True
                        else:
                            self.logger.warning(f"Failed to login to Proxmox at {host}: {resp.status_code}")
                            # self.logger.debug(f"Response body: {resp.text}")  # too verbose
                        
                except requests.exceptions.Timeout:
                    self.logger.warning(f"Connection timeout to {host}")
                    self.is_connected = False
                    self.connection_error = f"Timeout connecting to {host}"
                except requests.exceptions.ConnectionError:
                    self.logger.warning(f"Cannot connect to {host}")
                    self.is_connected = False
                    self.connection_error = f"Cannot connect to {host}"
                except Exception as e:
                    self.logger.warning(f"Error connecting to {host}: {e}")
                    self.is_connected = False
                    self.connection_error = str(e)
            
            self.logger.error(f"Failed to connect to any Proxmox host (tried {len(hosts_to_try)} hosts)")
            self.is_connected = False
            return False
    
    def _auto_discover_fallback_hosts(self):
        # find other nodes in cluster
        try:
            h = self.current_host or self.config.host
            url = f"https://{h}:8006/api2/json/nodes"
            r = self._create_session().get(url, timeout=10)
            
            if r.status_code != 200:
                return
            
            nodes = r.json().get('data', [])
            discovered = []
            
            for node in nodes:
                node_name = node.get('node')
                if node.get('status') == 'online':
                    node_ip = self._get_node_ip(node_name)
                    if node_ip and node_ip != self.config.host:
                        # _get_node_ip already does reachability probing
                        discovered.append(node_ip)
                        self.logger.info(f"Fallback host discovered: {node_name} -> {node_ip}")
            
            if discovered:
                self.config.fallback_hosts = discovered
                self.logger.info(f"Auto-discovered {len(discovered)} fallback hosts: {discovered}")
                save_config()
            else:
                self.logger.info("No reachable fallback hosts discovered (all nodes unreachable or single-node cluster)")
                
        except Exception as e:
            self.logger.debug(f"Could not auto-discover fallback hosts: {e}")
    
    def _get_api_url(self, path: str) -> str:
        host = self.current_host or self.config.host
        return f"https://{host}:8006/api2/json{path}"
    
    def get_node_status(self) -> Dict[str, Any]:
        # gets node status, calculates load score
        # MK: made this parallel, was super slow before
        if not self.is_connected or not self.session:
            # return cached ha status if disconnected
            if self.ha_node_status:
                return {
                    name: {
                        'status': data.get('status', 'offline'),
                        'cpu_percent': 0,
                        'mem_percent': 0,
                        'mem_used': 0,
                        'mem_total': 0,
                        'disk_percent': 0,
                        'disk_used': 0,
                        'disk_total': 0,
                        'netin': 0,
                        'netout': 0,
                        'score': 0,
                        'uptime': 0,
                        'offline': data.get('status') == 'offline',
                        'last_seen': data.get('last_seen').isoformat() if data.get('last_seen') else None
                    }
                    for name, data in self.ha_node_status.items()
                }
            return {}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            response = self._api_get(url)
            
            if response.status_code == 200:
                nodes = response.json()['data']
                node_status = {}
                
                api_nodes = set()
                
                # fetch node details (parallel if gevent available)
                def fetch_node_details(node):
                    node_name = node['node']
                    try:
                        status_url = f"https://{host}:8006/api2/json/nodes/{node_name}/status"
                        status_response = self._create_session().get(status_url, timeout=10)
                        if status_response.status_code == 200:
                            return (node_name, node, status_response.json()['data'])
                        else:
                            return (node_name, node, None)
                    except Exception as e:
                        # self.logger.debug(f"node {node_name} error: {e}")  # too noisy
                        return (node_name, node, None)
                
                # parallel if available
                if GEVENT_AVAILABLE and GEVENT_POOL:
                    tasks = [lambda n=node: fetch_node_details(n) for node in nodes]
                    results = run_concurrent(tasks, timeout=15.0)
                else:
                    results = [fetch_node_details(node) for node in nodes]
                
                # Process results
                for result in results:
                    if result is None:
                        continue
                    
                    node_name, node, status_data = result
                    api_nodes.add(node_name)
                    
                    if status_data:
                        self.logger.debug(f"Raw status data for {node_name}: {status_data}")
                        
                        # Calculate percentages
                        cpu_percent = status_data.get('cpu', 0) * 100
                        mem_used = status_data.get('memory', {}).get('used', 0)
                        mem_total = status_data.get('memory', {}).get('total', 1)
                        mem_percent = (mem_used / mem_total) * 100 if mem_total > 0 else 0
                        
                        # Disk stats from rootfs
                        rootfs = status_data.get('rootfs', {})
                        disk_used = rootfs.get('used', 0)
                        disk_total = rootfs.get('total', 1)
                        disk_percent = (disk_used / disk_total) * 100 if disk_total > 0 else 0
                        
                        # Network stats (cumulative bytes)
                        netin = status_data.get('netin', 0)
                        netout = status_data.get('netout', 0)
                        
                        # Calculate simple score (lower is better)
                        score = cpu_percent + mem_percent
                        
                        # Check maintenance status
                        in_maintenance = node_name in self.nodes_in_maintenance
                        maintenance_task = None
                        maintenance_acknowledged = False
                        if in_maintenance:
                            task_obj = self.nodes_in_maintenance[node_name]
                            maintenance_task = task_obj.to_dict()
                            maintenance_acknowledged = task_obj.acknowledged
                        
                        # Check update status
                        is_updating = node_name in self.nodes_updating
                        update_task = None
                        if is_updating:
                            update_task = self.nodes_updating[node_name].to_dict()
                        
                        node_status[node_name] = {
                            'status': node.get('status', 'unknown'),
                            'cpu_percent': round(cpu_percent, 2),
                            'mem_percent': round(mem_percent, 2),
                            'mem_used': mem_used,
                            'mem_total': mem_total,
                            'disk_percent': round(disk_percent, 2),
                            'disk_used': disk_used,
                            'disk_total': disk_total,
                            'netin': netin,
                            'netout': netout,
                            'score': round(score, 2),
                            'uptime': status_data.get('uptime', 0),
                            'maintenance_mode': in_maintenance,
                            'maintenance_task': maintenance_task,
                            'maintenance_acknowledged': maintenance_acknowledged,
                            'is_updating': is_updating,
                            'update_task': update_task,
                            'offline': False
                        }
                        
                        maintenance_str = " [MAINTENANCE]" if in_maintenance else ""
                        update_str = " [UPDATING]" if is_updating else ""
                        self.logger.info(f"Node {node_name}: CPU {cpu_percent:.2f}%, RAM {mem_percent:.2f}% ({self._format_bytes(mem_used)}/{self._format_bytes(mem_total)}), Score {score:.2f}, Status: {node['status']}{maintenance_str}{update_str}")
                    else:
                        # Node exists but we couldn't get status - might be offline
                        node_status[node_name] = {
                            'status': node.get('status', 'unknown'),
                            'cpu_percent': 0,
                            'mem_percent': 0,
                            'mem_used': 0,
                            'mem_total': 0,
                            'disk_percent': 0,
                            'disk_used': 0,
                            'disk_total': 0,
                            'netin': 0,
                            'netout': 0,
                            'score': 0,
                            'uptime': 0,
                            'offline': node.get('status') != 'online'
                        }
                
                # Add offline nodes from HA tracking that weren't in API response
                for ha_node, ha_data in self.ha_node_status.items():
                    if ha_node not in api_nodes and ha_data.get('status') == 'offline':
                        node_status[ha_node] = {
                            'status': 'offline',
                            'cpu_percent': 0,
                            'mem_percent': 0,
                            'mem_used': 0,
                            'mem_total': 0,
                            'disk_percent': 0,
                            'disk_used': 0,
                            'disk_total': 0,
                            'netin': 0,
                            'netout': 0,
                            'score': 0,
                            'uptime': 0,
                            'offline': True,
                            'last_seen': ha_data.get('last_seen').isoformat() if ha_data.get('last_seen') else None
                        }
                        self.logger.info(f"Node {ha_node}: OFFLINE (from HA tracking)")
                
                return node_status
            else:
                # Session might have expired - don't immediately mark as disconnected
                # LW: the _api_get already handles connection state
                self.logger.warning(f"Failed to get nodes (status {response.status_code})")
                return {}
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            # Connection error - _api_get handles the failure counter
            return {}
        except Exception as e:
            self.logger.error(f"Error getting node status: {e}")
            return {}
    
    def get_vm_resources(self) -> list:
        # NS: fetches VMs + CTs, adds computed mem/cpu percentages
        if not self.is_connected or not self.session: return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/resources"
            resp = self._create_session().get(url, params={'type': 'vm'}, timeout=10)
            
            if resp.status_code != 200: return []
            
            # NS: success - reset failure counter
            self._consecutive_failures = 0
            
            resources = resp.json()['data']
            resources.sort(key=lambda x: x.get('vmid', 0))  # consistent order
            
            # add percentage values for UI
            for r in resources:
                maxmem = r.get('maxmem', 0)
                r['mem_percent'] = round((r.get('mem', 0) / maxmem) * 100, 1) if maxmem > 0 else 0
                r['cpu_percent'] = round(r.get('cpu', 0) * 100, 1)
            
            return resources
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            # LW: don't immediately mark disconnected, use failure counter
            return []
        except:
            return []
    
    # MK: old version, keeping around just in case
    def get_vm_resources_v1(self) -> list:
        if not self.is_connected: return []
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/resources"
            r = self._create_session().get(url, params={'type': 'vm'}, timeout=10)
            return r.json().get('data', []) if r.status_code == 200 else []
        except:
            return []
    
    def _format_bytes(self, bytes_value: int) -> str:
        # NS: quick helper, nothing fancy
        gb = bytes_value / (1024 ** 3)
        if gb >= 1: return f"{gb:.2f} GB"
        mb = bytes_value / (1024 ** 2)
        return f"{mb:.2f} MB"
    
    # same thing but different format, used somewhere?
    def _fmt_bytes(self, b):
        if b >= 1024**3: return f"{b/1024**3:.1f}G"
        if b >= 1024**2: return f"{b/1024**2:.1f}M"
        return f"{b/1024:.1f}K"
    
    def check_balance_needed(self, node_status: Dict[str, Any]) -> tuple:
        """
        Check if cluster needs rebalancing based on node scores.
        
        NS: The scoring algorithm here is inspired by ProxLB by gyptazy
        (https://github.com/gyptazy/ProxLB) - great project, thanks for 
        open-sourcing it! We adapted it for our multi-cluster setup.
        
        LW: Now also excludes nodes configured in excluded_nodes setting
        """
        if not node_status:
            return False, None, None
        
        # LW: Get excluded nodes from config
        config_excluded = getattr(self.config, 'excluded_nodes', []) or []
        
        # Exclude nodes in maintenance AND configured excluded nodes from balancing decisions
        # MK: This was a bug before - we'd try to migrate TO maintenance nodes
        active_nodes = {
            node: data for node, data in node_status.items() 
            if data['status'] == 'online' 
            and not data.get('maintenance_mode', False)
            and node not in config_excluded
        }
        
        if config_excluded:
            self.logger.debug(f"Excluding configured nodes from balance check: {config_excluded}")
        
        scores = [(node, data['score']) for node, data in active_nodes.items()]
        if len(scores) < 2:
            self.logger.info("Not enough online nodes for balancing (excluding maintenance and excluded nodes)")
            return False, None, None
        
        scores.sort(key=lambda x: x[1])
        min_node, min_score = scores[0]
        max_node, max_score = scores[-1]
        
        score_diff = max_score - min_score
        threshold_value = self.config.migration_threshold
        
        # self.logger.debug(f"scores: {scores}")  # very spammy
        self.logger.info(f"Score difference: {score_diff:.2f} (Min: {min_node}={min_score:.2f}, Max: {max_node}={max_score:.2f})")
        self.logger.info(f"Migration threshold: {threshold_value}%")
        
        if score_diff > threshold_value:
            self.logger.info(f"[WARN] Balance needed! Score difference {score_diff:.2f} > threshold {threshold_value}")
            return True, max_node, min_node
        else:
            self.logger.info(f"[OK] Cluster is balanced. Score difference {score_diff:.2f} <= threshold {threshold_value}")
            return False, None, None
    
    def _check_affinity_violation(self, vmid, target_node, vm_nodes=None):
        """Check if moving a VM/CT would violate affinity rules

        NS: Feb 2026 - reads directly from DB for speed (called in a loop by
        find_migration_candidate). Works for QEMU and LXC (GitHub Issue #73).
        MK: returns enforce flag so caller can decide to block or just warn
        """
        try:
            rules = get_db().get_affinity_rules(self.id).get(self.id, [])
        except Exception as e:
            self.logger.error(f"Failed to load affinity rules: {e}")
            return {'violation': False}

        if not rules:
            return {'violation': False}

        # LW: caller can pass pre-built map to avoid repeated API calls
        if vm_nodes is None:
            vm_nodes = {}
            try:
                for res in self.get_vm_resources():
                    if res.get('type') in ('qemu', 'lxc'):
                        vm_nodes[str(res.get('vmid'))] = res.get('node')
            except:
                return {'violation': False}

        vid = str(vmid)

        for rule in rules:
            if not rule.get('enabled', True):
                continue

            rtype = rule.get('type', 'together')
            # MK: handle both field names, this mismatch was a pain to track down
            rule_vms = [str(v) for v in (rule.get('vm_ids') or rule.get('vms', []))]

            if vid not in rule_vms:
                continue

            # where are the other VMs/CTs in this rule?
            other_nodes = set()
            for v in rule_vms:
                if v != vid and v in vm_nodes:
                    other_nodes.add(vm_nodes[v])

            if rtype == 'together' and other_nodes and target_node not in other_nodes:
                return {
                    'violation': True, 'enforce': rule.get('enforce', False),
                    'rule': rule.get('name', 'Affinity Rule'),
                    'message': f"VM/CT {vmid} must stay with IDs {', '.join([v for v in rule_vms if v != vid])} on node {list(other_nodes)[0]}"
                }
            elif rtype == 'separate' and target_node in other_nodes:
                conflicting = [v for v in rule_vms if v != vid and vm_nodes.get(v) == target_node]
                return {
                    'violation': True, 'enforce': rule.get('enforce', False),
                    'rule': rule.get('name', 'Anti-Affinity Rule'),
                    'message': f"VM/CT {vmid} must not be on same node as IDs {', '.join(conflicting)}"
                }

        return {'violation': False}

    def find_migration_candidate(self, source_node: str, target_node: str, exclude_vmids: list = None, include_containers: bool = None) -> Optional[Dict]:
        """
        Find the best VM to migrate from source to target node.
        
        NS: This logic is based on ProxLB's approach but we've added:
        - Affinity rule checking
        - HA status awareness  
        - Multi-cluster considerations
        
        Priority order:
        1. VMs on shared storage (easiest to migrate)
        2. VMs on local storage (only if balance_local_disks enabled)
        3. Smaller VMs first (less impact during migration)
        4. Prefer QEMU VMs over containers (containers need restart)
        
        MK: Container migrations are tricky - they ALWAYS restart.
        We learned this the hard way in production...
        LW: Feb 2026 - exclude_vmids used for multi-migration cycles to avoid re-picking
        """
        if exclude_vmids is None:
            exclude_vmids = []
        vms = self.get_vm_resources()
        if not vms:
            return None
        
        # MK: Get excluded VMs for this cluster
        excluded_vmids = self.get_balancing_excluded_vms()
        if excluded_vmids:
            self.logger.info(f"VMs excluded from balancing: {excluded_vmids}")
        
        # Filter VMs on source node that are running
        candidates = [
            vm for vm in vms 
            if vm.get('node') == source_node and 
            vm.get('status') == 'running' and
            vm.get('type') in ['qemu', 'lxc'] and
            vm.get('vmid') not in excluded_vmids and  # MK: Skip excluded VMs
            vm.get('vmid') not in exclude_vmids  # LW: Skip already-migrated VMs this cycle
        ]
        
        # Log if any VMs were excluded
        excluded_on_node = [vm for vm in vms if vm.get('node') == source_node and vm.get('vmid') in excluded_vmids]
        if excluded_on_node:
            self.logger.info(f"Skipping {len(excluded_on_node)} excluded VM(s) on {source_node}: {[vm.get('vmid') for vm in excluded_on_node]}")
        
        # Filter out containers if balance_containers is disabled
        # NS: include_containers override allows cross-cluster LB to use group-level setting
        balance_ct = include_containers if include_containers is not None else getattr(self.config, 'balance_containers', False)
        if not balance_ct:
            original_count = len(candidates)
            candidates = [vm for vm in candidates if vm.get('type') != 'lxc']
            skipped = original_count - len(candidates)
            if skipped > 0:
                self.logger.info(f"Skipping {skipped} container(s) - container balancing is disabled")
        
        if not candidates:
            self.logger.info(f"No running VMs found on {source_node} for migration")
            return None
        
        # Check setting for local disk migration
        balance_local_disks = getattr(self.config, 'balance_local_disks', False)
        
        # Check each candidate for local disks and filter accordingly
        migratable_candidates = []
        local_disk_candidates = []  # VMs with local disks (need special handling)
        
        for vm in candidates:
            vmid = vm.get('vmid')
            vm_type = vm.get('type')
            storage_type = self.check_vm_storage_type(source_node, vmid, vm_type)
            
            if storage_type == 'local':
                if balance_local_disks:
                    # Mark as local disk VM for migration with --with-local-disks
                    vm['_has_local_disks'] = True
                    local_disk_candidates.append(vm)
                    self.logger.info(f"Found {vm.get('name', 'unnamed')} (VMID {vmid}) with local storage - eligible for migration (balance_local_disks enabled)")
                else:
                    self.logger.info(f"Skipping {vm.get('name', 'unnamed')} (VMID {vmid}) - uses local storage (enable 'Balance Local Disks' to include)")
                continue
            elif storage_type == 'unknown':
                self.logger.warning(f"Could not determine storage type for {vm.get('name', 'unnamed')} (VMID {vmid}) - skipping to be safe")
                continue
            
            vm['_has_local_disks'] = False
            migratable_candidates.append(vm)
        
        # Prefer VMs on shared storage, but include local disk VMs if enabled and no shared ones available
        all_candidates = migratable_candidates + local_disk_candidates
        
        if not all_candidates:
            self.logger.info(f"No migratable VMs found on {source_node}")
            return None
        
        # Sort by: shared storage first, then VMs over containers, then by memory (smallest first)
        all_candidates.sort(key=lambda x: (x.get('_has_local_disks', False), x.get('type') == 'lxc', x.get('mem', 0)))
        
        # LW: build vm->node map once for affinity checks
        vm_nodes = {}
        for res in vms:
            if res.get('type') in ('qemu', 'lxc'):
                vm_nodes[str(res.get('vmid'))] = res.get('node')

        for vm in all_candidates:
            vm_type = 'CT' if vm.get('type') == 'lxc' else 'VM'
            local_warning = ' [LOCAL DISKS]' if vm.get('_has_local_disks') else ''
            restart_warning = ' (will restart!)' if vm.get('type') == 'lxc' else ''
            self.logger.info(f"Potential migration candidate: {vm.get('name', 'unnamed')} ({vm_type} {vm.get('vmid')}, RAM: {self._format_bytes(vm.get('mem', 0))}){local_warning}{restart_warning}")

        # NS: Feb 2026 - Check affinity rules before picking candidate (Issue #73)
        # MK: simulate the move first so the check sees the VM's new position
        selected = None
        for candidate in all_candidates:
            cid = str(candidate.get('vmid'))
            old_node = vm_nodes.get(cid)
            vm_nodes[cid] = target_node
            aff = self._check_affinity_violation(candidate.get('vmid'), target_node, vm_nodes)
            vm_nodes[cid] = old_node  # restore

            if aff.get('violation'):
                if aff.get('enforce'):
                    self.logger.warning(f"Skipping {candidate.get('name', 'unnamed')} (VMID {candidate.get('vmid')}) - enforced affinity rule '{aff['rule']}': {aff['message']}")
                    continue
                else:
                    # not enforced, just warn
                    self.logger.warning(f"Affinity warning for {candidate.get('name', 'unnamed')} (VMID {candidate.get('vmid')}) - rule '{aff['rule']}': {aff['message']} (allowing)")

            selected = candidate
            break

        if not selected:
            self.logger.info(f"No migratable VMs on {source_node} (all blocked by enforced affinity rules)")
            return None

        vm_type = 'CT' if selected.get('type') == 'lxc' else 'VM'
        if selected.get('_has_local_disks'):
            self.logger.warning(f"Selected for migration: {selected.get('name', 'unnamed')} ({vm_type} {selected.get('vmid')}) - HAS LOCAL DISKS (will use --with-local-disks)")
        elif selected.get('type') == 'lxc':
            self.logger.warning(f"Selected container for migration: {selected.get('name', 'unnamed')} ({vm_type} {selected.get('vmid')}) - WILL CAUSE DOWNTIME!")
        else:
            self.logger.info(f"Selected for migration: {selected.get('name', 'unnamed')} ({vm_type} {selected.get('vmid')})")
        return selected
    
    def get_best_target_node(self, exclude_nodes: List[str] = None) -> Optional[str]:
        """Find the best target node for migration
        
        LW: Now also excludes nodes configured in excluded_nodes (like ProxLB)
        """
        if exclude_nodes is None:
            exclude_nodes = []
        
        # NS: GitHub #40 - Exclude rebooting nodes
        if hasattr(self, '_rolling_update') and self._rolling_update:
            rebooting = self._rolling_update.get('rebooting_nodes', [])
            if rebooting:
                exclude_nodes = list(set(exclude_nodes + rebooting))
                self.logger.debug(f"Excluding rebooting nodes: {rebooting}")
        
        # LW: Also exclude nodes configured in cluster settings
        config_excluded = getattr(self.config, 'excluded_nodes', []) or []
        all_excluded = list(set(exclude_nodes + config_excluded))
        
        if config_excluded:
            self.logger.debug(f"Excluding configured nodes from balancing: {config_excluded}")
        
        node_status = self.get_node_status()
        
        # Filter available nodes
        available_nodes = [
            (node, data) for node, data in node_status.items()
            if data['status'] == 'online' 
            and not data.get('maintenance_mode', False)
            and node not in all_excluded
        ]
        
        if not available_nodes:
            return None
        
        # Sort by score (lowest first)
        available_nodes.sort(key=lambda x: x[1]['score'])
        
        return available_nodes[0][0]
    
    def migrate_vm(self, vm: Dict, target_node: str, dry_run: bool = None) -> bool:
        """migrate vm to another node"""
        # NS: this handles the proxmox api call
        # MK: had to add iso unmount, was breaking migrations silently for weeks
        if dry_run is None:
            dry_run = self.config.dry_run
        
        # dry run = just log, dont actually do it
        if dry_run:
            self.logger.info(f"[DRY RUN] Would migrate {vm.get('name', 'unnamed')} ({vm.get('vmid')}) to {target_node}")
            self.last_migration_log.append({
                'timestamp': datetime.now().isoformat(),
                'vm': vm.get('name', 'unnamed'),
                'vmid': vm.get('vmid'),
                'from_node': vm.get('node'),
                'to_node': target_node,
                'dry_run': True,
                'success': True
            })
            return True
        
        try:
            vmid = vm.get('vmid')
            source_node = vm.get('node')
            vm_type = vm.get('type')
            # target_storage = vm.get('_target_storage')  # old code, not needed
            
            # unmount iso first or migration fails (found this out the hard way)
            if vm_type == 'qemu':
                config_url = f"https://{self.host}:8006/api2/json/nodes/{source_node}/qemu/{vmid}/config"
                config_response = self._create_session().get(config_url, timeout=15)
                if config_response.status_code == 200:
                    config = config_response.json().get('data', {})
                    for key in ['ide2', 'cdrom']:
                        if key in config and 'iso' in str(config.get(key, '')).lower():
                            iso_value = config[key]
                            self.logger.info(f"unmounting iso from {key}")
                            unmount_response = self._create_session().put(config_url, data={key: 'none,media=cdrom'})
                            if unmount_response.status_code != 200:
                                self.logger.warning(f"couldnt unmount iso: {unmount_response.text}")
            
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{source_node}/qemu/{vmid}/migrate"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{source_node}/lxc/{vmid}/migrate"
            
            data = {
                'target': target_node,
                'online': 1
            }
            
            # local disk handling
            has_local_disks = vm.get('_has_local_disks', False)
            if has_local_disks and vm_type == 'qemu':
                data['with-local-disks'] = 1
                self.logger.info(f"using with-local-disks flag")
            
            local_info = ' (local disks)' if has_local_disks else ''
            self.logger.info(f"migrating {vm.get('name', 'unnamed')} ({vmid}) {source_node} -> {target_node}{local_info}")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_id = response.json().get('data')
                self.logger.info(f"[OK] Migration initiated for {vm.get('name', 'unnamed')} to {target_node} (Task: {task_id})")
                
                # Wait for migration to complete
                if task_id:
                    success = self._wait_for_task(source_node, task_id)
                    if success:
                        self.logger.info(f"[OK] Successfully migrated {vm.get('name', 'unnamed')} to {target_node}")
                        self.last_migration_log.append({
                            'timestamp': datetime.now().isoformat(),
                            'vm': vm.get('name', 'unnamed'),
                            'vmid': vmid,
                            'from_node': source_node,
                            'to_node': target_node,
                            'dry_run': False,
                            'success': True
                        })
                        return True
                    else:
                        self.logger.error(f"[ERROR] Migration task failed for {vm.get('name', 'unnamed')}")
                        self.last_migration_log.append({
                            'timestamp': datetime.now().isoformat(),
                            'vm': vm.get('name', 'unnamed'),
                            'vmid': vmid,
                            'from_node': source_node,
                            'to_node': target_node,
                            'dry_run': False,
                            'success': False,
                            'error': 'Task failed'
                        })
                        return False
                
                return True
            else:
                self.logger.error(f"[ERROR] Failed to migrate {vm.get('name', 'unnamed')}: {response.status_code} - {response.text}")
                self.last_migration_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'vm': vm.get('name', 'unnamed'),
                    'vmid': vmid,
                    'from_node': source_node,
                    'to_node': target_node,
                    'dry_run': False,
                    'success': False,
                    'error': response.text
                })
                return False
                
        except Exception as e:
            self.logger.error(f"[ERROR] Error migrating VM: {e}")
            return False
    
    def _wait_for_task(self, node: str, task_id: str, timeout: int = 600) -> bool:
        """
        Wait for a Proxmox task to complete.
        
        MK: This polls the task status endpoint until the task is done or times out.
        Used after migrations, backups, etc. to ensure they complete before proceeding.
        
        Polling interval: 2s normally, 5s after errors (to avoid hammering a failing node)
        Default timeout: 10 minutes (should be enough for most migrations)
        
        Returns True only if task completed with exitstatus 'OK'.
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/tasks/{task_id}/status"
                response = self._api_get(url)
                
                if response.status_code == 200:
                    task_status = response.json()['data']
                    status = task_status.get('status')
                    
                    if status == 'stopped':
                        # Task finished - check if successful
                        exit_status = task_status.get('exitstatus', '')
                        return exit_status == 'OK'
                    
                time.sleep(2)  # Poll every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error checking task status: {e}")
                time.sleep(5)  # Back off on errors
        
        self.logger.error(f"Task {task_id} timed out after {timeout} seconds")
        return False
    
    def enter_maintenance_mode(self, node_name: str, skip_evacuation: bool = False) -> MaintenanceTask:
        """enter maintenance mode for a node, optionally skip VM evacuation"""
        with self.maintenance_lock:
            if node_name in self.nodes_in_maintenance:
                return self.nodes_in_maintenance[node_name]
            
            task = MaintenanceTask(node_name)
            self.nodes_in_maintenance[node_name] = task
        
        self.logger.info(f"[MAINT] Entering maintenance mode for node: {node_name}")

        if skip_evacuation:
            # MK: Skip evacuation - for non-reboot updates where user accepts the risk
            self.logger.warning(f"[MAINT] Skipping VM evacuation for {node_name} - VMs may be affected if update fails!")
            task.status = 'completed'
            task.total_vms = 0
            task.migrated_vms = 0
        elif self.config.ha_enabled and self._try_native_ha_maintenance(node_name, task):
            # NS feb 2026 - use native HA maintenance when available (#78)
            pass  # task already marked as completed by _try_native_ha_maintenance
        else:
            # Fallback: custom evacuation logic
            t = threading.Thread(target=self._evacuate_node, args=(node_name, task))
            t.daemon = True
            t.start()

        return task

    # NS feb 2026 - native Proxmox HA maintenance mode (#78)
    def _try_native_ha_maintenance(self, node_name, task):
        """Try to enable native HA maintenance via ha-manager. Returns True on success."""
        try:
            node_ip = self._get_node_ip(node_name)
            if not node_ip:
                self.logger.warning(f"[MAINT] Cannot resolve IP for {node_name}, falling back to custom evacuation")
                return False

            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')

            cmd = f"ha-manager crm-command node-maintenance enable {node_name}"
            self.logger.info(f"[MAINT] Trying native HA maintenance for {node_name}")

            # Try SSH auth methods in order: key -> passwordless -> password
            success = False
            if ssh_key:
                success = self._ssh_run_command_with_key(node_ip, ssh_user, cmd, ssh_key)
            if not success:
                success = self._ssh_run_command(node_ip, ssh_user, cmd)
            if not success and ssh_password:
                success = self._ssh_run_command_with_password(node_ip, ssh_user, cmd, ssh_password)

            if success:
                task.native_ha = True
                task.status = 'completed'
                task.total_vms = 0
                task.migrated_vms = 0
                self.logger.info(f"[MAINT] Native HA maintenance enabled for {node_name} - Proxmox will handle evacuation")
                return True
            else:
                self.logger.warning(f"[MAINT] Native HA maintenance failed for {node_name}, falling back to custom evacuation")
                return False

        except Exception as e:
            self.logger.warning(f"[MAINT] Native HA maintenance error for {node_name}: {e}, falling back to custom evacuation")
            return False

    def _evacuate_node(self, node_name: str, task: MaintenanceTask):
        # move all VMs off this node
        try:
            task.status = 'evacuating'
            
            # Get all VMs on this node
            vms = self.get_vm_resources()
            node_vms = [
                vm for vm in vms 
                if vm.get('node') == node_name and 
                vm.get('status') == 'running' and
                vm.get('type') in ['qemu', 'lxc']
            ]
            
            task.total_vms = len(node_vms)
            task.pending_vms = node_vms.copy()
            
            if task.total_vms == 0:
                self.logger.info(f"[OK] No running VMs on {node_name}, maintenance mode ready")
                task.status = 'completed'
                return
            
            self.logger.info(f"[PKG] Found {task.total_vms} VMs to evacuate from {node_name}")
            
            # Sort VMs by memory (smallest first for faster evacuation)
            node_vms.sort(key=lambda x: x.get('mem', 0))
            
            for vm in node_vms:
                vm_name = vm.get('name', 'unnamed')
                vmid = vm.get('vmid')
                
                task.current_vm = {'vmid': vmid, 'name': vm_name}
                
                # Find best target node
                target_node = self.get_best_target_node(exclude_nodes=[node_name])
                
                if not target_node:
                    self.logger.error(f"[ERROR] No available target node for {vm_name}")
                    task.failed_vms.append({'vmid': vmid, 'name': vm_name, 'error': 'No target node available'})
                    task.pending_vms = [v for v in task.pending_vms if v.get('vmid') != vmid]
                    continue
                
                self.logger.info(f"[SYNC] Evacuating {vm_name} (VMID: {vmid}) to {target_node}")
                
                # Perform migration (never dry run during evacuation)
                success = self.migrate_vm(vm, target_node, dry_run=False)
                
                if success:
                    task.migrated_vms += 1
                    self.logger.info(f"[OK] Evacuated {vm_name} to {target_node} ({task.migrated_vms}/{task.total_vms})")
                else:
                    task.failed_vms.append({'vmid': vmid, 'name': vm_name, 'error': 'Migration failed'})
                    self.logger.error(f"[ERROR] Failed to evacuate {vm_name}")
                
                task.pending_vms = [v for v in task.pending_vms if v.get('vmid') != vmid]
            
            task.current_vm = None
            
            if len(task.failed_vms) == 0:
                task.status = 'completed'
                self.logger.info(f"[OK] Maintenance mode ready for {node_name} - all VMs evacuated")
            else:
                task.status = 'completed_with_errors'
                self.logger.warning(f"[WARN] Maintenance mode for {node_name} completed with {len(task.failed_vms)} failed migrations")
                
        except Exception as e:
            self.logger.error(f"[ERROR] Error during evacuation: {e}")
            task.status = 'failed'
            task.error = str(e)
    
    def exit_maintenance_mode(self, node_name: str) -> bool:
        was_native_ha = False
        with self.maintenance_lock:
            if node_name in self.nodes_in_maintenance:
                was_native_ha = self.nodes_in_maintenance[node_name].native_ha
                del self.nodes_in_maintenance[node_name]
                self.logger.info(f"[OK] Exited maintenance mode for node: {node_name}")
            else:
                return False

        # NS feb 2026 - disable native HA maintenance outside the lock (#78)
        if was_native_ha:
            self._try_disable_native_ha_maintenance(node_name)

        return True

    # NS feb 2026 - disable native HA maintenance mode (#78)
    def _try_disable_native_ha_maintenance(self, node_name):
        try:
            node_ip = self._get_node_ip(node_name)
            if not node_ip:
                self.logger.warning(f"[MAINT] Cannot resolve IP for {node_name} to disable HA maintenance")
                return

            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')

            cmd = f"ha-manager crm-command node-maintenance disable {node_name}"

            success = False
            if ssh_key:
                success = self._ssh_run_command_with_key(node_ip, ssh_user, cmd, ssh_key)
            if not success:
                success = self._ssh_run_command(node_ip, ssh_user, cmd)
            if not success and ssh_password:
                success = self._ssh_run_command_with_password(node_ip, ssh_user, cmd, ssh_password)

            if success:
                self.logger.info(f"[MAINT] Native HA maintenance disabled for {node_name}")
            else:
                self.logger.error(f"[MAINT] Failed to disable native HA maintenance for {node_name} - manual intervention may be needed")
                self.logger.error(f"[MAINT] Fix: SSH to any cluster node and run: ha-manager crm-command node-maintenance disable {node_name}")

        except Exception as e:
            self.logger.error(f"[MAINT] Error disabling native HA maintenance for {node_name}: {e}")
    
    def get_maintenance_status(self, node_name: str) -> Optional[Dict]:
        with self.maintenance_lock:
            if node_name in self.nodes_in_maintenance:
                return self.nodes_in_maintenance[node_name].to_dict()
            return None
    
    # =====================================================
    # HIGH AVAILABILITY (HA) FUNCTIONS
    # NS: Our own HA implementation - doesn't use Proxmox HA
    # Monitors nodes and can restart VMs on other nodes if one fails
    # Oct 2025: Added quorum host checking for 2-node clusters
    # =====================================================
    
    def _ha_discover_fallback_hosts(self):
        # find all node IPs for fallback
        self.logger.info("[HA] Auto-discovering cluster node IPs for fallback...")
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return
        
        try:
            h = self.current_host or self.config.host
            url = f"https://{h}:8006/api2/json/nodes"
            r = self._create_session().get(url, timeout=10)
            
            if r.status_code != 200:
                self.logger.error(f"[HA] Failed to get nodes for auto-discovery")
                return
            
            nodes = r.json().get('data', [])
            discovered_hosts = []
            skipped = []
            
            for node in nodes:
                node_name = node.get('node')
                node_ip = self._get_node_ip(node_name)
                
                if node_ip and node_ip != self.config.host:
                    discovered_hosts.append(node_ip)
                    self.logger.info(f"[HA] Discovered fallback host: {node_name} -> {node_ip}")
                elif node_ip == self.config.host:
                    pass  # This is the primary, skip
                else:
                    skipped.append(node_name)
                    self.logger.warning(f"[HA] Could not find reachable IP for node '{node_name}' - skipped")
            
            # Update fallback hosts
            self.config.fallback_hosts = discovered_hosts
            self.logger.info(f"[HA] Auto-configured {len(discovered_hosts)} fallback hosts: {discovered_hosts}")
            if skipped:
                self.logger.warning(f"[HA] Nodes without reachable management IP: {skipped}")
            
            # Save config
            save_config()
            
        except Exception as e:
            self.logger.error(f"[HA] Error discovering fallback hosts: {e}")
    
    def _ha_update_fallback_hosts(self):
        # update fallback hosts periodically
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            response = self._create_session().get(url, timeout=10)
            
            if response.status_code != 200:
                return
            
            nodes = response.json().get('data', [])
            current_hosts = set()
            
            for node in nodes:
                node_name = node.get('node')
                if node.get('status') == 'online':
                    node_ip = self._get_node_ip(node_name)
                    if node_ip and node_ip != self.config.host:
                        current_hosts.add(node_ip)
            
            # Update if changed
            if set(self.config.fallback_hosts or []) != current_hosts:
                old_hosts = self.config.fallback_hosts
                self.config.fallback_hosts = list(current_hosts)
                self.logger.info(f"[HA] Updated fallback hosts: {old_hosts} -> {list(current_hosts)}")
                save_config()
                
        except Exception as e:
            self.logger.debug(f"[HA] Error updating fallback hosts: {e}")
    
    def start_ha_monitor(self):
        # start HA thread
        if self.ha_thread and self.ha_thread.is_alive():
            self.logger.info("HA monitor already running")
            return
        
        # Auto-discover fallback hosts
        self._ha_discover_fallback_hosts()
        
        # Check cluster size and warn about 2-node clusters
        try:
            if self.is_connected or self.connect_to_proxmox():
                host = self.current_host or self.config.host
                url = f"https://{host}:8006/api2/json/nodes"
                resp = self._create_session().get(url, timeout=10)
                if resp.status_code == 200:
                    nodes = resp.json().get('data', [])
                    node_count = len(nodes)
                    
                    if node_count == 2:
                        self.logger.warning("[HA] ════════════════════════════════════════════════════════")
                        self.logger.warning("[HA] 2-NODE CLUSTER DETECTED!")
                        self.logger.warning("[HA] ")
                        self.logger.warning("[HA] In a 2-node Proxmox cluster, when one node fails,")
                        self.logger.warning("[HA] the surviving node loses quorum and cannot start VMs!")
                        self.logger.warning("[HA] ")
                        self.logger.warning("[HA] RECOMMENDED SOLUTIONS:")
                        self.logger.warning("[HA] 1. Add a QDevice: pvecm qdevice setup <third-machine-IP>")
                        self.logger.warning("[HA] 2. Configure fencing in HA settings (IPMI/iLO)")
                        self.logger.warning("[HA] 3. Enable 'force_quorum_on_failure' (DANGEROUS!)")
                        self.logger.warning("[HA] ════════════════════════════════════════════════════════")
                    elif node_count == 1:
                        self.logger.warning("[HA] Single-node cluster - HA has limited functionality")
                    else:
                        self.logger.info(f"[HA] Cluster has {node_count} nodes - quorum should work normally")
        except Exception as e:
            self.logger.debug(f"[HA] Could not check cluster size: {e}")
        
        self.ha_enabled = True
        self.config.ha_enabled = True
        self.ha_thread = threading.Thread(target=self._ha_monitor_loop, daemon=True)
        self.ha_thread.start()
        self.logger.info("[HA] High Availability monitor started (checking every 10s)")  # 10s hardcoded for now
        
        # ═══════════════════════════════════════════════════════════════
        # AUTOMATIC SPLIT-BRAIN PROTECTION SETUP - NS Jan 2026
        # No manual configuration needed!
        # ═══════════════════════════════════════════════════════════════
        
        # Auto-discover shared storage if not already configured
        if not self.ha_config.get('storage_heartbeat_path'):
            self.logger.info("[HA] 🔍 Auto-discovering shared storages...")
            storage_path = self._ha_get_best_shared_storage_path()
            
            if storage_path:
                self.logger.info(f"[HA] ✓ Found shared storage: {storage_path}")
                self.ha_config['storage_heartbeat_path'] = storage_path
                self.ha_config['storage_heartbeat_enabled'] = True
                self.ha_config['dual_network_mode'] = True
                
                # Auto-install agents in background
                def auto_install():
                    time.sleep(5)  # Wait for HA to fully start
                    self.logger.info("[HA] 🔧 Auto-installing node agents...")
                    results = self._ha_install_agents_on_all_nodes()
                    success = sum(1 for v in results.values() if v)
                    self.logger.info(f"[HA] ✓ Node agents: {success}/{len(results)} installed")
                
                threading.Thread(target=auto_install, daemon=True).start()
            else:
                self.logger.warning("[HA] ⚠️ No shared storage found - SSH-only protection mode")
                self.logger.warning("[HA] ⚠️ Add shared storage (NFS/CephFS) for full dual-network protection")
        
        # Start storage-based heartbeat if configured
        if self.ha_config.get('storage_heartbeat_enabled') and self.ha_config.get('storage_heartbeat_path'):
            self._ha_storage_heartbeat_init()
            self.logger.info("[HA] ✓ Storage-based split-brain protection ACTIVE")
            self.logger.info(f"[HA] ✓ Heartbeat path: {self.ha_config.get('storage_heartbeat_path')}")
        else:
            self.logger.info("[HA] Split-brain protection: SSH verification active")
        
        # Restart self-fence agents if they were installed - NS Jan 2026
        if self.ha_config.get('self_fence_installed'):
            self.logger.info("[HA] 🛡️ Restarting self-fence agents on nodes...")
            threading.Thread(target=self._ha_start_self_fence_agents, daemon=True).start()
    
    def stop_ha_monitor(self):
        self.ha_enabled = False
        self.config.ha_enabled = False
        
        # Stop storage heartbeat thread
        if self.ha_heartbeat_thread and self.ha_heartbeat_thread.is_alive():
            self.ha_heartbeat_stop.set()
            self.ha_heartbeat_thread.join(timeout=5)
            self.logger.info("[HA] Storage heartbeat thread stopped")
        
        # Stop self-fence agents on nodes (but don't uninstall) - NS Jan 2026
        if self.ha_config.get('self_fence_installed'):
            self.logger.info("[HA] Stopping self-fence agents on nodes...")
            threading.Thread(target=self._ha_stop_self_fence_agents, daemon=True).start()
        
        self.logger.info("[HA] High Availability monitor stopped")
    
    def _ha_monitor_loop(self):
        # main loop - checks every 10s
        self.logger.info("[HA] HA monitor loop started")
        update_counter = 0
        
        while self.ha_enabled and not self.stop_event.is_set():
            try:
                self._ha_check_nodes()
                
                # Update fallback hosts every 60 seconds (6 iterations)
                update_counter += 1
                if update_counter >= 6:
                    self._ha_update_fallback_hosts()
                    update_counter = 0
                    
            except Exception as e:
                self.logger.error(f"[HA] Error in HA monitor: {e}")
            
            # Wait 10 seconds between checks
            for _ in range(10):
                if not self.ha_enabled or self.stop_event.is_set():
                    break
                time.sleep(1)
        
        self.logger.info("[HA] HA monitor loop ended")
    
    def _ha_check_nodes(self):
        if not self.is_connected:
            if not self.connect_to_proxmox():
                self.logger.error("[HA] Cannot connect to Proxmox for HA check")
                return
        
        try:
            # Use current connected host
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                self.logger.error(f"[HA] Failed to get nodes: {resp.status_code}")
                # Try to reconnect (might switch to fallback host)
                self.session = None
                self.connect_to_proxmox()
                return
            
            nodes = resp.json().get('data', [])
            current_time = datetime.now()
            
            with self.ha_lock:
                for node in nodes:
                    node_name = node.get('node')
                    node_status = node.get('status', 'unknown')
                    
                    # init tracking for new nodes
                    if node_name not in self.ha_node_status:
                        self.ha_node_status[node_name] = {
                            'last_seen': current_time,
                            'status': 'online',
                            'consecutive_failures': 0,
                            'last_status': node_status
                        }
                    
                    prev_status = self.ha_node_status[node_name]['status']
                    
                    if node_status == 'online':
                        # Node is healthy
                        self.ha_node_status[node_name]['last_seen'] = current_time
                        self.ha_node_status[node_name]['consecutive_failures'] = 0
                        
                        if prev_status == 'offline':
                            self.logger.info(f"[HA] ✓ Node {node_name} is back ONLINE")
                            self.ha_node_status[node_name]['status'] = 'online'
                            # Clear recovery flag
                            self.ha_recovery_in_progress.pop(node_name, None)
                            
                            # NS: Restore quorum if all nodes are back online
                            self._ha_check_restore_quorum()
                            
                            # Broadcast node online event
                            try:
                                broadcast_sse('node_status', {
                                    'node': node_name,
                                    'status': 'online',
                                    'event': 'node_online',
                                    'message': f'Node {node_name} is back online',
                                    'cluster_id': self.id
                                }, self.id)
                            except Exception as e:
                                self.logger.error(f"[HA] Failed to broadcast node online: {e}")
                    else:
                        # Node appears offline
                        self.ha_node_status[node_name]['consecutive_failures'] += 1
                        failures = self.ha_node_status[node_name]['consecutive_failures']
                        
                        self.logger.warning(f"[HA] ⚠ Node {node_name} check failed ({failures}/{self.ha_failure_threshold})")
                        
                        if failures >= self.ha_failure_threshold:
                            if prev_status == 'online':
                                self.logger.error(f"[HA] ✗ Node {node_name} declared OFFLINE after {failures} failures!")
                                self.ha_node_status[node_name]['status'] = 'offline'
                                
                                # Broadcast node offline event immediately
                                try:
                                    broadcast_sse('node_status', {
                                        'node': node_name,
                                        'status': 'offline',
                                        'event': 'node_offline',
                                        'message': f'Node {node_name} is offline!',
                                        'cluster_id': self.id,
                                        'severity': 'critical'
                                    }, self.id)
                                except Exception as e:
                                    self.logger.error(f"[HA] Failed to broadcast node offline: {e}")
                                
                                # Skip if in maintenance or already recovering
                                if node_name in self.nodes_in_maintenance:
                                    self.logger.info(f"[HA] Node {node_name} is in maintenance, skipping HA recovery")
                                elif node_name in self.ha_recovery_in_progress:
                                    self.logger.info(f"[HA] Recovery already in progress for {node_name}")
                                else:
                                    # Trigger HA recovery
                                    self._ha_trigger_recovery(node_name)
                    
                    self.ha_node_status[node_name]['last_status'] = node_status
                    
        except Exception as e:
            self.logger.error(f"[HA] Error checking nodes: {e}")
    
    def _ha_trigger_recovery(self, failed_node: str):
        """trigger HA recovery for a failed node - restart VMs on surviving nodes"""
        self.logger.info(f"[HA] ========== STARTING HA RECOVERY FOR {failed_node} ==========")
        
        # Mark recovery in progress
        self.ha_recovery_in_progress[failed_node] = True
        
        # Start recovery in background thread
        recovery_thread = threading.Thread(
            target=self._ha_recovery_worker,
            args=(failed_node,),
            daemon=True
        )
        recovery_thread.start()
    
    def _ha_recovery_worker(self, failed_node: str):
        
        try:
            # ============================================
            # STEP 0: Try to acquire recovery lock (if storage configured)
            # ============================================
            if self.ha_config.get('storage_heartbeat_enabled'):
                if not self._ha_acquire_recovery_lock(failed_node):
                    self.logger.warning(f"[HA] Another instance is already recovering {failed_node}")
                    return
            
            # ============================================
            # SPLIT-BRAIN PREVENTION STEP 1: Wait period
            # ============================================
            recovery_delay = self.ha_config.get('recovery_delay', 30)
            self.logger.info(f"[HA] Waiting {recovery_delay}s before recovery (split-brain prevention)...")
            time.sleep(recovery_delay)
            
            # Check if node came back online during wait
            with self.ha_lock:
                if failed_node in self.ha_node_status:
                    if self.ha_node_status[failed_node].get('status') == 'online':
                        self.logger.info(f"[HA] Node {failed_node} came back online - cancelling recovery")
                        self._ha_release_recovery_lock(failed_node)
                        return
            
            # ============================================
            # SPLIT-BRAIN PREVENTION STEP 2: SSH CHECK (AUTOMATIC!)
            # ============================================
            # This is the KEY to automatic split-brain prevention:
            # If we can SSH to the "dead" node, it's actually alive!
            # This means we have a NETWORK SPLIT, not a node failure.
            
            self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
            self.logger.info(f"[HA] STEP 2: AUTOMATIC SPLIT-BRAIN CHECK")
            self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
            
            node_is_alive = False
            running_vms = []
            running_cts = []
            
            # Method 1: SSH Check (works if server network is up)
            self.logger.info(f"[HA] 2a. Checking via SSH...")
            ssh_check = self._ha_check_node_via_ssh(failed_node)
            
            if ssh_check['reachable']:
                node_is_alive = True
                running_vms = ssh_check.get('running_vms', [])
                running_cts = ssh_check.get('running_cts', [])
                self.logger.warning(f"[HA] ⚠️ Node {failed_node} IS REACHABLE via SSH!")
            
            # Method 2: Storage Heartbeat Check (works even if server network is down!)
            # This is CRITICAL for dual-network setups!
            if self.ha_config.get('dual_network_mode') or self.ha_config.get('storage_heartbeat_enabled'):
                self.logger.info(f"[HA] 2b. Checking via STORAGE HEARTBEAT (survives server network failure)...")
                
                heartbeat = self._ha_check_node_agent_heartbeat(failed_node)
                
                if heartbeat.get('alive'):
                    age = heartbeat.get('age_seconds', 0)
                    self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
                    self.logger.critical(f"[HA] ⚠️ NODE {failed_node} STORAGE HEARTBEAT IS ACTIVE!")
                    self.logger.critical(f"[HA] ⚠️ Heartbeat age: {age:.1f}s (timeout: {self.ha_config.get('storage_heartbeat_timeout', 30)}s)")
                    self.logger.critical(f"[HA] ⚠️ Node is ALIVE on storage network!")
                    self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
                    node_is_alive = True
                    # Get VMs from heartbeat if we didn't get them from SSH
                    if not running_vms:
                        running_vms = heartbeat.get('running_vms', [])
                    if not running_cts:
                        running_cts = heartbeat.get('running_cts', [])
                elif heartbeat.get('age_seconds') is not None:
                    self.logger.info(f"[HA] ✓ Storage heartbeat is STALE ({heartbeat.get('age_seconds'):.1f}s old)")
                else:
                    self.logger.info(f"[HA] No storage heartbeat found for {failed_node}")
            
            # Now handle based on combined results
            if node_is_alive:
                # NODE IS ALIVE! This is a network split!
                self.logger.critical(f"[HA] ☠️ SPLIT-BRAIN RISK DETECTED!")
                self.logger.critical(f"[HA] Node {failed_node} is ALIVE but not responding to Proxmox API")
                self.logger.critical(f"[HA] This is a NETWORK PARTITION, not a node failure!")
                
                has_running_vms = bool(running_vms or running_cts)
                
                if has_running_vms:
                    # CRITICAL: Must stop VMs on the partitioned node first!
                    self.logger.critical(f"[HA] ═══════════════════════════════════════════════════════")
                    self.logger.critical(f"[HA] STOPPING VMs ON PARTITIONED NODE TO PREVENT CORRUPTION")
                    self.logger.critical(f"[HA] Running VMs: {running_vms}")
                    self.logger.critical(f"[HA] Running CTs: {running_cts}")
                    self.logger.critical(f"[HA] ═══════════════════════════════════════════════════════")
                    
                    vms_stopped = False
                    
                    # Try SSH method first
                    if ssh_check['reachable']:
                        vms_stopped = self._ha_ssh_stop_vms_on_node(
                            failed_node, 
                            vmids=running_vms,
                            ctids=running_cts,
                            reachable_ips=ssh_check.get('reachable_ips', [])
                        )
                    
                    # If SSH didn't work, use poison pill via storage
                    if not vms_stopped and (self.ha_config.get('dual_network_mode') or self.ha_config.get('storage_heartbeat_enabled')):
                        self.logger.info(f"[HA] SSH stop failed, using POISON PILL via storage...")
                        if self._ha_write_poison_pill(failed_node, "Recovery initiated - stop all VMs"):
                            # Wait for the node agent to see the poison and stop VMs
                            self.logger.info(f"[HA] Waiting 30s for node agent to stop VMs...")
                            time.sleep(30)
                            
                            # Check if VMs stopped
                            heartbeat = self._ha_check_node_agent_heartbeat(failed_node)
                            if not heartbeat.get('running_vms') and not heartbeat.get('running_cts'):
                                vms_stopped = True
                                self.logger.info(f"[HA] ✓ Poison pill worked - VMs stopped")
                            else:
                                self.logger.warning(f"[HA] ⚠️ VMs may still be running after poison pill")
                    
                    if not vms_stopped:
                        strict_mode = self.ha_config.get('strict_fencing', False)
                        if strict_mode:
                            self.logger.error(f"[HA] ✗ STRICT MODE: Could not stop VMs on {failed_node} - ABORTING!")
                            self._ha_release_recovery_lock(failed_node)
                            return
                        else:
                            self.logger.warning(f"[HA] ⚠️ Could not confirm VMs stopped on {failed_node}")
                            self.logger.warning(f"[HA] ⚠️ Proceeding anyway - SPLIT-BRAIN RISK EXISTS!")
                    else:
                        self.logger.info(f"[HA] ✓ VMs stopped on {failed_node}")
                        
                    # Wait a moment for VMs to fully stop
                    self.logger.info(f"[HA] Waiting 10s for VMs to fully stop...")
                    time.sleep(10)
                else:
                    self.logger.info(f"[HA] No running VMs on {failed_node} - safe to proceed")
            else:
                # Node is truly unreachable on ALL networks - safe to proceed
                self.logger.info(f"[HA] ✓ Node {failed_node} confirmed UNREACHABLE (SSH failed, no storage heartbeat)")
                self.logger.info(f"[HA] ✓ Safe to proceed with recovery")
            
            # ============================================
            # ENSURE CONNECTION (might need to switch hosts)
            # ============================================
            if self.current_host and failed_node in self.current_host:
                self.logger.warning(f"[HA] Currently connected to failing node {self.current_host}, reconnecting...")
                self.session = None
                self.is_connected = False
            
            if not self.is_connected or not self.session:
                if not self.connect_to_proxmox():
                    self.logger.error(f"[HA] Cannot connect to any Proxmox node for recovery!")
                    self._ha_release_recovery_lock(failed_node)
                    return
                self.logger.info(f"[HA] Connected to {self.current_host} for recovery operations")
            
            # ============================================
            # SPLIT-BRAIN PREVENTION STEP 3: Quorum check
            # ============================================
            if self.ha_config.get('quorum_enabled', True):
                if not self._ha_check_quorum():
                    self.logger.error(f"[HA] ✗ NO QUORUM - Cannot proceed with recovery!")
                    self.logger.error(f"[HA] This prevents split-brain: we might be the isolated node")
                    self.logger.error(f"[HA] Configure quorum_hosts in HA config or disable quorum check")
                    self._ha_release_recovery_lock(failed_node)
                    return
                self.logger.info(f"[HA] ✓ Quorum confirmed - safe to proceed with recovery")
            
            # ============================================
            # SPLIT-BRAIN PREVENTION STEP 4: Network check
            # ============================================
            if self.ha_config.get('verify_network_before_recovery', True):
                if not self._ha_verify_network():
                    self.logger.error(f"[HA] ✗ Network verification failed - we might be isolated!")
                    self.logger.error(f"[HA] Not proceeding with recovery to prevent split-brain")
                    self._ha_release_recovery_lock(failed_node)
                    return
                self.logger.info(f"[HA] ✓ Network connectivity confirmed")
            
            # ============================================
            # Optional: Hardware fencing (IPMI/iLO if configured)
            # ============================================
            fenced = self._ha_fence_node(failed_node)
            if fenced:
                self.logger.info(f"[HA] ✓ Hardware fencing successful for {failed_node}")
            
            # Get list of VMs that were on the failed node
            vms_on_failed_node = self._ha_get_vms_on_node(failed_node)
            
            if not vms_on_failed_node:
                self.logger.info(f"[HA] No VMs found on failed node {failed_node}")
                self._ha_release_recovery_lock(failed_node)
                return
            
            self.logger.info(f"[HA] Found {len(vms_on_failed_node)} VMs on failed node {failed_node}")
            
            # Get available target nodes
            available_nodes = self._ha_get_available_nodes(exclude_node=failed_node)
            
            if not available_nodes:
                self.logger.error(f"[HA] No available nodes for HA recovery!")
                return
            
            # Special handling for 2-node cluster
            # recovery order is by vmid ascending, lowest id gets started first
            # (consistent ordering prevents races when both nodes try to recover)
            if len(available_nodes) == 1:
                self.logger.warning(f"[HA] 2-NODE CLUSTER DETECTED - Only {available_nodes[0]} available for recovery")
                self.logger.warning(f"[HA] All VMs will be started on {available_nodes[0]}")
            
            self.logger.info(f"[HA] Available target nodes: {available_nodes}")
            
            # For each VM, check storage type and try to recover
            recovered = 0
            failed = 0
            skipped_local = 0
            
            for vm in vms_on_failed_node:
                vmid = vm.get('vmid')
                vm_name = vm.get('name', f'VM {vmid}')
                vm_type = vm.get('type', 'qemu')
                
                # check VM uses shared storage
                storage_type = self._ha_check_vm_storage(vmid, vm_type, failed_node)
                
                if storage_type == 'local':
                    self.logger.warning(f"[HA] ⚠ SKIPPING {vm_name} ({vmid}) - Uses LOCAL storage, cannot recover!")
                    self.logger.warning(f"[HA]   → To enable HA for this VM, move its disks to shared storage")
                    skipped_local += 1
                    continue
                
                # Select target node (round-robin or least loaded)
                target_node = self._ha_select_target_node(available_nodes, vm)
                
                if not target_node:
                    self.logger.error(f"[HA] No target node available for {vm_name}")
                    failed += 1
                    continue
                
                self.logger.info(f"[HA] Attempting to recover {vm_name} ({vmid}) to {target_node}")
                
                # Try to start the VM on the target node
                # Note: This relies on shared storage - the VM config should already be available
                success = self._ha_start_vm_on_node(vmid, vm_type, target_node, failed_node)
                
                if success:
                    self.logger.info(f"[HA] ✓ Successfully recovered {vm_name} on {target_node}")
                    recovered += 1
                else:
                    self.logger.error(f"[HA] ✗ Failed to recover {vm_name}")
                    failed += 1
                
                # Small delay between VM starts
                time.sleep(2)
            
            self.logger.info(f"[HA] ========== HA RECOVERY COMPLETE ==========")
            self.logger.info(f"[HA] Recovered: {recovered}, Failed: {failed}, Skipped (local storage): {skipped_local}")
            
            if skipped_local > 0:
                self.logger.warning(f"[HA] {skipped_local} VMs were skipped because they use local storage!")
                self.logger.warning(f"[HA] Move these VMs to shared storage for full HA protection.")
            
        except Exception as e:
            self.logger.error(f"[HA] Error in recovery worker: {e}")
        finally:
            # Release recovery lock
            self._ha_release_recovery_lock(failed_node)
            
            # Keep recovery flag for a while to prevent duplicate recovery
            time.sleep(60)  # 60s cooldown, maybe make this configurable?
            self.ha_recovery_in_progress.pop(failed_node, None)
    
    def _ha_check_vm_storage(self, vmid: int, vm_type: str, node: str) -> str:
        """check if VM uses shared or local storage

        MK: checks proxmox 'shared' flag since LVM/ZFS can go either way
        """
        try:
            host = self.current_host or self.config.host
            
            # Get VM config
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            response = self._create_session().get(url, timeout=10)
            
            if response.status_code != 200:
                return 'unknown'
            
            config = response.json().get('data', {})
            
            # Get storage configurations
            storage_url = f"https://{host}:8006/api2/json/storage"
            storage_response = self._create_session().get(storage_url, timeout=10)
            storage_configs = {}
            if storage_response.status_code == 200:
                for s in storage_response.json().get('data', []):
                    storage_configs[s['storage']] = s
            
            shared_types = ['nfs', 'cifs', 'glusterfs', 'cephfs', 'rbd', 'iscsi', 'iscsidirect', 'drbd', 'pbs']
            local_types = ['dir', 'lvmthin']
            # NS: LVM/ZFS treated as local unless proxmox 'shared' flag is set
            # Claude helped optimize this logic - NS feb 2026

            has_local = False
            has_shared = False
            
            for key, value in config.items():
                # Check QEMU disks (scsi0, virtio0, ide0, sata0, etc.)
                if vm_type == 'qemu' and any(key.startswith(p) for p in ['scsi', 'virtio', 'ide', 'sata', 'efidisk', 'tpmstate']):
                    if isinstance(value, str) and ':' in value:
                        storage_name = value.split(':')[0]
                        if storage_name in storage_configs:
                            storage_cfg = storage_configs[storage_name]
                            storage_type = storage_cfg.get('type', '')
                            is_shared_flag = storage_cfg.get('shared', 0)

                            if is_shared_flag:
                                has_shared = True
                            elif storage_type in shared_types:
                                has_shared = True
                            elif storage_type in local_types:
                                has_local = True
                            else:
                                has_local = True

                # Check LXC rootfs and mount points
                if vm_type == 'lxc' and (key == 'rootfs' or key.startswith('mp')):
                    if isinstance(value, str) and ':' in value:
                        storage_name = value.split(':')[0]
                        if storage_name in storage_configs:
                            storage_cfg = storage_configs[storage_name]
                            storage_type = storage_cfg.get('type', '')
                            is_shared_flag = storage_cfg.get('shared', 0)
                            
                            if is_shared_flag:
                                has_shared = True
                            elif storage_type in shared_types:
                                has_shared = True
                            elif storage_type in local_types:
                                has_local = True
                            else:
                                has_local = True

            # If any disk is local, the VM can't be recovered
            if has_local:
                return 'local'
            elif has_shared:
                return 'shared'
            else:
                return 'unknown'
                
        except Exception as e:
            self.logger.debug(f"[HA] Error checking VM storage: {e}")
            return 'unknown'
    
    def get_balancing_excluded_vms(self) -> List[int]:
        """Get list of VMIDs excluded from load balancing for this cluster
        
        MK: VMs can be excluded from balancing in the VM config.
        This is useful for VMs with GPU passthrough, local-only storage,
        or other reasons why they shouldn't be migrated automatically.
        """
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'SELECT vmid FROM balancing_excluded_vms WHERE cluster_id = ?',
                (self.id,)
            )
            return [row['vmid'] for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting excluded VMs: {e}")
            return []
    
    def set_vm_balancing_excluded(self, vmid: int, excluded: bool, reason: str = None, user: str = 'system') -> bool:
        """Set whether a VM should be excluded from load balancing
        
        LW: Added Jan 2026 for pinned VMs - some people run HA or manually placed VMs
        MK: Uses INSERT OR REPLACE for older SQLite compat (upsert syntax is 3.24+)
        
        Returns True on success, False on error.
        """
        try:
            db = get_db()
            cursor = db.conn.cursor()
            
            # MK: Ensure table exists (migration for existing databases)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cluster_id TEXT NOT NULL,
                    vmid INTEGER NOT NULL,
                    reason TEXT,
                    created_by TEXT,
                    created_at TEXT,
                    UNIQUE(cluster_id, vmid)
                )
            ''')
            
            if excluded:
                # MK: Use INSERT OR REPLACE for SQLite compatibility
                cursor.execute('''
                    INSERT OR REPLACE INTO balancing_excluded_vms (cluster_id, vmid, reason, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (self.id, vmid, reason, user, datetime.now().isoformat()))
                self.logger.info(f"VM {vmid} excluded from balancing (reason: {reason})")
            else:
                cursor.execute(
                    'DELETE FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                    (self.id, vmid)
                )
                self.logger.info(f"VM {vmid} removed from balancing exclusion")
            
            db.conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Error setting VM balancing exclusion: {e}")
            return False
    
    def is_vm_balancing_excluded(self, vmid: int) -> dict:
        """Check if a VM is excluded from balancing and get the reason"""
        try:
            db = get_db()
            cursor = db.conn.cursor()
            cursor.execute(
                'SELECT vmid, reason, created_by, created_at FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                (self.id, vmid)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'excluded': True,
                    'reason': row['reason'],
                    'created_by': row['created_by'],
                    'created_at': row['created_at']
                }
            return {'excluded': False}
        except Exception as e:
            self.logger.error(f"Error checking VM balancing exclusion: {e}")
            return {'excluded': False}
    
    def check_vm_storage_type(self, node: str, vmid: int, vm_type: str) -> str:
        # public wrapper for _ha_check_vm_storage
        return self._ha_check_vm_storage(vmid, vm_type, node)
    
    def _ha_get_vms_on_node(self, node: str) -> List[Dict]:
        try:
            # Ensure we're connected to a working node
            if not self.is_connected:
                if not self.connect_to_proxmox():
                    self.logger.error(f"[HA] Cannot connect to get VMs on {node}")
                    return []
            
            h = self.current_host or self.config.host
            url = f"https://{h}:8006/api2/json/cluster/resources"
            r = self._create_session().get(url, params={'type': 'vm'}, timeout=10)
            
            if r.status_code == 200:
                res = r.json().get('data', [])
                # Get VMs that were on the failed node AND were running
                vms = [x for x in res if x.get('node') == node and x.get('status') == 'running']
                self.logger.info(f"[HA] Found {len(vms)} running VMs on node {node}")
                return vms
            else:
                self.logger.error(f"[HA] Failed to get cluster resources: {r.status_code}")
            return []
        except Exception as e:
            self.logger.error(f"[HA] Error getting VMs on node: {e}")
            return []
    
    def _ha_get_available_nodes(self, exclude_node: str = None) -> List[str]:
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            response = self._create_session().get(url, timeout=10)
            
            if response.status_code == 200:
                nodes = response.json().get('data', [])
                available = []
                for n in nodes:
                    nm = n.get('node')
                    if nm == exclude_node: continue
                    if n.get('status') != 'online': continue
                    if nm in self.nodes_in_maintenance: continue
                    available.append(nm)
                return available
            return []
        except:
            return []
    
    def _ha_select_target_node(self, available_nodes: List[str], vm: Dict) -> Optional[str]:
        # pick least loaded node
        if not available_nodes:
            return None
        
        node_status = self.get_node_status()
        
        if not node_status:
            return available_nodes[0]  # fallback
        
        # Sort by score (lower is better)
        scored_nodes = []
        for node in available_nodes:
            if node in node_status:
                score = node_status[node].get('score', 100)
                scored_nodes.append((node, score))
            else:
                scored_nodes.append((node, 50))  # Default score
        
        scored_nodes.sort(key=lambda x: x[1])
        return scored_nodes[0][0] if scored_nodes else None
    
    def _ha_start_vm_on_node(self, vmid: int, vm_type: str, target_node: str, original_node: str) -> bool:
        """Attempt to start a VM on a target node after HA failover
        
        CRITICAL FOR 2-NODE CLUSTERS:
        1. FIRST force quorum (otherwise pmxcfs is read-only!)
        2. THEN move config, clear locks, start VM
        
        Without quorum, /etc/pve is read-only and nothing works!
        """
        host = self.current_host or self.config.host
        
        try:
            # Force quorum first (for 2-node clusters)
            # Without quorum, pmxcfs is read-only - we can't do anything!
            two_node_mode = self.ha_config.get('two_node_mode', False)
            force_quorum = self.ha_config.get('force_quorum_on_failure', False)
            
            if two_node_mode or force_quorum:
                self.logger.info(f"[HA] Forcing quorum on {target_node} (2-node mode)")
                
                if self._ha_try_force_quorum(target_node):
                    self.logger.info(f"[HA] ✓ Quorum forced successfully")
                    time.sleep(3)  # Give corosync/pmxcfs time to update
                else:
                    self.logger.error(f"[HA] ✗ Could not force quorum - SSH access required!")
                    self.logger.error(f"[HA] Manual fix: SSH to {target_node} and run: pvecm expected 1")
                    # Continue anyway - maybe it will work
            
            # Try to fence the dead node (if fencing is configured)
            self.logger.info(f"[HA] Attempting to fence {original_node}")
            fenced = self._ha_fence_node(original_node)
            if not fenced:
                self.logger.warning(f"[HA] ⚠ Could not fence node {original_node}")
            
            # Check current VM status
            self.logger.info(f"[HA] Checking VM {vmid} status")
            try:
                status_url = f"https://{host}:8006/api2/json/cluster/resources"
                status_resp = self._create_session().get(status_url, params={'type': 'vm'}, timeout=10)
                if status_resp.status_code == 200:
                    resources = status_resp.json().get('data', [])
                    vm_resource = next((r for r in resources if r.get('vmid') == vmid), None)
                    if vm_resource:
                        vm_status = vm_resource.get('status')
                        vm_node = vm_resource.get('node')
                        self.logger.info(f"[HA] VM {vmid} current state: {vm_status} on {vm_node}")
            except Exception as e:
                self.logger.warning(f"[HA] Could not check VM state: {e}")
            
            # Clear any locks on the VM
            self.logger.info(f"[HA] Clearing locks on VM {vmid}")
            if not self._ha_clear_vm_lock(vmid, vm_type, target_node, original_node):
                self.logger.warning(f"[HA] ⚠ Failed to clear lock on {vm_type}/{vmid} - continuing anyway")
            
            # Move VM config to target node
            # The config must be in /etc/pve/nodes/<target>/qemu-server/<vmid>.conf
            self.logger.info(f"[HA] Moving VM {vmid} config from {original_node} to {target_node}")
            config_moved = self._ha_move_vm_config(vmid, vm_type, original_node, target_node)
            if config_moved:
                self.logger.info(f"[HA] ✓ VM {vmid} config moved to {target_node}")
                time.sleep(2)  # Give pmxcfs time to sync
            else:
                self.logger.warning(f"[HA] Could not move config - will try to start anyway")
            
            # Start the VM on target node
            self.logger.info(f"[HA] Starting VM {vmid} on {target_node}")
            
            if vm_type == 'qemu':
                start_url = f"https://{host}:8006/api2/json/nodes/{target_node}/qemu/{vmid}/status/start"
            else:
                start_url = f"https://{host}:8006/api2/json/nodes/{target_node}/lxc/{vmid}/status/start"
            
            start_response = self._create_session().post(start_url, timeout=15)
            
            if start_response.status_code == 200:
                self.logger.info(f"[HA] ✓ VM {vmid} started successfully on {target_node}")
                return True
            
            error_text = start_response.text.lower()
            self.logger.error(f"[HA] Failed to start VM {vmid}: {start_response.text}")
            
            # Handle specific errors
            if 'no quorum' in error_text or 'cluster not ready' in error_text:
                self.logger.error(f"[HA] ✗ Still no quorum - force quorum may have failed")
                if not (two_node_mode or force_quorum):
                    self.logger.error(f"[HA] Enable '2-Node Cluster Mode' in HA settings!")
                return False
            
            if 'does not exist' in error_text or 'not found' in error_text:
                self.logger.error(f"[HA] ✗ VM config not found on {target_node}")
                self.logger.error(f"[HA] Config move may have failed - check SSH access")
                return False
            
            # Try with skiplock if there's a lock (only works for root@pam)
            if 'lock' in error_text and self.config.user.lower().startswith('root@'):
                self.logger.info(f"[HA] VM {vmid} has lock, trying with skiplock=1")
                start_response = self._create_session().post(start_url, data={'skiplock': 1}, timeout=15)
                if start_response.status_code == 200:
                    self.logger.info(f"[HA] ✓ VM {vmid} started with skiplock")
                    return True
            
            return False
                    
        except Exception as e:
            self.logger.error(f"[HA] Error starting VM {vmid} on {target_node}: {e}")
            return False
    
    def _ha_check_quorum(self) -> bool:
        """check if we have quorum by pinging external hosts

        NS: crucial for 2-node clusters - prevents split-brain
        """
        quorum_hosts = self.ha_config.get('quorum_hosts', [])
        gateway = self.ha_config.get('quorum_gateway')
        required_votes = self.ha_config.get('quorum_required_votes', 2)
        
        # Build list of hosts to check
        hosts_to_check = list(quorum_hosts)
        if gateway:
            hosts_to_check.insert(0, gateway)
        
        # If no quorum hosts configured, try to auto-detect
        if not hosts_to_check:
            # Try common external hosts
            hosts_to_check = [
                '8.8.8.8',      # Google DNS
                '1.1.1.1',      # Cloudflare DNS
                '9.9.9.9',      # Quad9 DNS
            ]
            self.logger.debug(f"[HA] No quorum hosts configured, using defaults: {hosts_to_check}")
        
        # Count successful pings
        votes = 0
        for host in hosts_to_check:
            if self._ha_ping_host(host):
                votes += 1
                self.logger.debug(f"[HA] Quorum vote from {host}: ✓")
            else:
                self.logger.debug(f"[HA] Quorum vote from {host}: ✗")
        
        # We always count ourselves as 1 vote
        total_possible = len(hosts_to_check) + 1  # +1 for ourselves
        votes += 1  # Our own vote
        
        has_quorum = votes >= required_votes
        
        self.ha_have_quorum = has_quorum
        self.ha_last_quorum_check = datetime.now()
        
        self.logger.info(f"[HA] Quorum check: {votes}/{total_possible} votes (need {required_votes})")
        
        return has_quorum
    
    def _ha_verify_network(self) -> bool:
        """Verify network connectivity before HA recovery
        
        This is an additional safety check beyond quorum.
        We verify we can reach important infrastructure.
        """
        check_hosts = self.ha_config.get('network_check_hosts', [])
        required = self.ha_config.get('network_check_required', 1)
        
        # If no hosts configured, use gateway or skip
        if not check_hosts:
            gateway = self.ha_config.get('quorum_gateway')
            if gateway:
                check_hosts = [gateway]
            else:
                # Try to detect default gateway
                try:
                    result = subprocess.run(
                        ['ip', 'route', 'show', 'default'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and 'via' in result.stdout:
                        gateway = result.stdout.split('via')[1].split()[0]
                        check_hosts = [gateway]
                except:
                    pass
        
        if not check_hosts:
            self.logger.debug("[HA] No network check hosts, skipping verification")
            return True
        
        successful = 0
        for host in check_hosts:
            if self._ha_ping_host(host):
                successful += 1
        
        if successful >= required:
            return True
        else:
            self.logger.warning(f"[HA] Network check: only {successful}/{len(check_hosts)} hosts reachable (need {required})")
            return False
    
    def _ha_ping_host(self, host: str, timeout: int = 3) -> bool:
        # ping check
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), host],
                capture_output=True, timeout=timeout + 2
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            # ping not available, try socket
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, 80))
                sock.close()
                return result == 0
            except:
                return False
        except Exception:
            return False
    
    def _ha_self_fence(self):
        """self-fence: stop our VMs if we lose quorum (2-node safety)"""
        if not self.ha_config.get('self_fence_enabled', True):
            return
        
        self.logger.error("[HA] ========== SELF-FENCING TRIGGERED ==========")
        self.logger.error("[HA] This node has lost quorum and will fence itself")
        self.logger.error("[HA] This prevents split-brain data corruption")
        
        # Mark that we should not start any VMs
        self.ha_have_quorum = False
        
        # If watchdog is enabled, trigger it
        if self.ha_config.get('watchdog_enabled', False):
            self.logger.error("[HA] Triggering hardware watchdog reboot in 60 seconds...")
            try:
                # Write to watchdog device - this will reboot the system
                # if not reset within the timeout
                with open('/dev/watchdog', 'w') as wd:
                    wd.write('V')  # Magic close character
                self.logger.error("[HA] Watchdog armed - system will reboot if quorum not restored")
            except Exception as e:
                self.logger.error(f"[HA] Could not arm watchdog: {e}")
    
    def _ha_fence_node(self, node: str) -> bool:
        """fence (power off) a node via IPMI/iLO/DRAC"""
        # check fencing is configured for this node
        fencing_config = getattr(self.config, 'fencing', {})
        node_fencing = fencing_config.get(node, {})
        
        if not node_fencing:
            self.logger.warning(f"[HA] No fencing configured for node {node}")
            self.logger.warning(f"[HA] Configure fencing in config: fencing.{node}.type = 'ipmi'")
            return False
        
        fence_type = node_fencing.get('type', '').lower()
        
        try:
            if fence_type == 'ipmi':
                # IPMI fencing
                ipmi_host = node_fencing.get('host')
                ipmi_user = node_fencing.get('user', 'ADMIN')
                ipmi_pass = node_fencing.get('password')
                
                if not ipmi_host or not ipmi_pass:
                    self.logger.error(f"[HA] IPMI fencing requires host and password")
                    return False
                
                self.logger.info(f"[HA] Fencing node {node} via IPMI at {ipmi_host}")
                
                # Power off via ipmitool
                result = subprocess.run(
                    ['ipmitool', '-I', 'lanplus', '-H', ipmi_host, 
                     '-U', ipmi_user, '-P', ipmi_pass, 'power', 'off'],
                    capture_output=True, timeout=30
                )
                
                if result.returncode == 0:
                    self.logger.info(f"[HA] ✓ Successfully fenced node {node}")
                    time.sleep(5)  # Wait for node to fully power off
                    return True
                else:
                    self.logger.error(f"[HA] IPMI fencing failed: {result.stderr.decode()}")
                    return False
                    
            elif fence_type == 'ssh':
                # SSH fencing (emergency shutdown)
                ssh_host = node_fencing.get('host', node)
                ssh_user = node_fencing.get('user', 'root')
                
                self.logger.info(f"[HA] Fencing node {node} via SSH shutdown")

                result = subprocess.run(
                    ['ssh', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                     f'{ssh_user}@{ssh_host}', 'poweroff'],
                    capture_output=True, timeout=15
                )
                
                # SSH might fail if node is really dead, that's OK
                time.sleep(10)  # Wait for shutdown
                return True
                
            elif fence_type == 'proxmox':
                # Use Proxmox's built-in HA fencing
                self.logger.info(f"[HA] Using Proxmox HA fencing for {node}")
                # Proxmox handles this automatically if HA is configured
                return True
                
            else:
                self.logger.warning(f"[HA] Unknown fencing type: {fence_type}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"[HA] Fencing timed out for {node}")
            return False
        except FileNotFoundError:
            self.logger.error(f"[HA] Fencing tool not found (ipmitool/ssh)")
            return False
        except Exception as e:
            self.logger.error(f"[HA] Fencing error for {node}: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATIC SPLIT-BRAIN PROTECTION - NS Jan 2026
    # 
    # ZERO MANUAL SETUP REQUIRED! Uses existing SSH credentials.
    #
    # How it works:
    # 1. Node appears dead (no API response)
    # 2. PegaProx tries SSH to the "dead" node
    # 3. If SSH works → Node is ALIVE (network split!)
    #    → Stop VMs on that node via SSH
    #    → Then start VMs on surviving node
    # 4. If SSH fails → Node is truly DEAD
    #    → Safe to start VMs on surviving node
    #
    # This prevents split-brain WITHOUT requiring:
    # - Manual agent installation
    # - Hardware fencing (IPMI/iLO)
    # - QDevice setup
    # - Shared storage configuration
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _ha_check_node_via_ssh(self, node: str) -> dict:
        """check if node is alive via SSH on ALL networks (split-brain prevention).
        returns dict with reachable, reachable_ips, has_running_vms, running_vms, has_storage_locks"""
        result = {
            'reachable': False, 
            'reachable_ips': [],
            'has_running_vms': False, 
            'running_vms': [], 
            'running_cts': [],
            'has_storage_locks': False
        }
        
        try:
            # Get ALL IPs for this node (all networks!)
            all_ips = self._ha_get_all_node_ips(node)
            
            if not all_ips:
                self.logger.warning(f"[HA] Cannot get any IP for node {node}")
                # Still check storage locks!
                lock_check = self._ha_check_vm_locks_on_storage(node)
                result['has_storage_locks'] = lock_check.get('has_active_locks', False)
                if result['has_storage_locks']:
                    self.logger.critical(f"[HA] ⚠️ Node {node} has ACTIVE STORAGE LOCKS!")
                    self.logger.critical(f"[HA] ⚠️ Node is likely alive on storage network!")
                    result['reachable'] = True  # Treat as reachable!
                return result
            
            self.logger.info(f"[HA] 🔍 Checking node {node} on ALL networks: {all_ips}")
            
            # Get SSH credentials from cluster config
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')
            
            # Try SSH on ALL IPs (parallel for speed - reduces worst-case from N*30s to 30s)
            check_cmd = "qm list 2>/dev/null | grep running | awk '{print $1}' | tr '\\n' ',' ; echo '|' ; pct list 2>/dev/null | grep running | awk '{print $1}' | tr '\\n' ','"

            def _try_ssh_ip(ip):
                """Try all SSH auth methods for one IP, return (ip, output) or None."""
                self.logger.info(f"[HA] Trying SSH to {node} via {ip}...")
                output = None
                if ssh_key:
                    output = self._ssh_run_command_with_key_output(ip, ssh_user, check_cmd, ssh_key)
                if output is None:
                    output = self._ssh_run_command_output(ip, ssh_user, check_cmd)
                if output is None and ssh_password:
                    output = self._ssh_run_command_with_password_output(ip, ssh_user, check_cmd, ssh_password)
                return (ip, output) if output is not None else None

            # Run SSH checks in parallel using gevent pool
            if GEVENT_AVAILABLE and len(all_ips) > 1:
                from gevent.pool import Pool as _Pool
                pool = _Pool(size=len(all_ips))
                ssh_results = pool.map(_try_ssh_ip, all_ips)
            else:
                ssh_results = [_try_ssh_ip(ip) for ip in all_ips]

            # First successful result wins
            for r in ssh_results:
                if r is not None:
                    ip, output = r
                    result['reachable'] = True
                    result['reachable_ips'].append(ip)
                    self.logger.warning(f"[HA] ⚠️ Node {node} IS REACHABLE via {ip}!")

                    # Parse output: "vmid1,vmid2,|ctid1,ctid2,"
                    parts = output.strip().split('|')
                    if len(parts) >= 1 and parts[0].strip():
                        vms = [v.strip() for v in parts[0].split(',') if v.strip()]
                        result['running_vms'] = vms
                    if len(parts) >= 2 and parts[1].strip():
                        cts = [c.strip() for c in parts[1].split(',') if c.strip()]
                        result['running_cts'] = cts

                    result['has_running_vms'] = bool(result['running_vms'] or result['running_cts'])
                    break
            
            if result['reachable']:
                self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
                self.logger.critical(f"[HA] ⚠️ NETWORK SPLIT DETECTED - NOT A NODE FAILURE!")
                self.logger.critical(f"[HA] Node {node} reachable via: {result['reachable_ips']}")
                self.logger.critical(f"[HA] Running VMs: {result['running_vms']}")
                self.logger.critical(f"[HA] Running CTs: {result['running_cts']}")
                self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
            else:
                # SSH failed on all IPs - but check storage locks as final safety check!
                self.logger.info(f"[HA] SSH failed on all IPs ({all_ips})")
                self.logger.info(f"[HA] Checking storage locks as final safety check...")
                
                lock_check = self._ha_check_vm_locks_on_storage(node)
                result['has_storage_locks'] = lock_check.get('has_active_locks', False)
                
                if result['has_storage_locks']:
                    self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
                    self.logger.critical(f"[HA] ⚠️ DANGER: SSH UNREACHABLE BUT STORAGE LOCKS ACTIVE!")
                    self.logger.critical(f"[HA] ⚠️ Node {node} may still be writing to storage!")
                    self.logger.critical(f"[HA] ⚠️ Locked VMs: {lock_check.get('locked_vms', [])}")
                    self.logger.critical(f"[HA] ════════════════════════════════════════════════════════")
                    # Treat as reachable to prevent split-brain!
                    result['reachable'] = True
                else:
                    self.logger.info(f"[HA] ✓ Node {node} confirmed UNREACHABLE (SSH failed, no storage locks)")
                
        except Exception as e:
            self.logger.error(f"[HA] Error in multi-network SSH check: {e}")
        
        return result
    
    def _ha_ssh_stop_vms_on_node(self, node: str, vmids: list = None, ctids: list = None, reachable_ips: list = None) -> bool:
        """stop VMs/CTs on a node via SSH (tries all IPs) - used during network split to stop VMs before failover"""
        try:
            # Use IPs that we know work, or get all IPs
            all_ips = reachable_ips if reachable_ips else self._ha_get_all_node_ips(node)
            if not all_ips:
                self.logger.error(f"[HA] No IPs available for node {node}")
                return False
            
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')
            
            self.logger.warning(f"[HA] ═══════════════════════════════════════════════════════")
            self.logger.warning(f"[HA] STOPPING VMs ON {node} VIA SSH (Split-Brain Prevention)")
            self.logger.warning(f"[HA] Trying IPs: {all_ips}")
            self.logger.warning(f"[HA] ═══════════════════════════════════════════════════════")
            
            # Find a working IP
            working_ip = None
            for ip in all_ips:
                # Quick connectivity test
                test_output = self._ssh_run_command_output(ip, ssh_user, "echo OK")
                if test_output is None and ssh_key:
                    test_output = self._ssh_run_command_with_key_output(ip, ssh_user, "echo OK", ssh_key)
                if test_output is None and ssh_password:
                    test_output = self._ssh_run_command_with_password_output(ip, ssh_user, "echo OK", ssh_password)
                
                if test_output is not None:
                    working_ip = ip
                    self.logger.info(f"[HA] Using IP {ip} for VM stop commands")
                    break
            
            if not working_ip:
                self.logger.error(f"[HA] Cannot reach node {node} on any IP!")
                return False
            
            stopped = []
            failed = []
            
            # Stop VMs
            if vmids:
                for vmid in vmids:
                    self.logger.info(f"[HA] Stopping VM {vmid} on {node}...")
                    stop_cmd = f"qm stop {vmid} --timeout 30 2>&1 || qm stop {vmid} --skiplock --timeout 30 2>&1"
                    
                    success = False
                    if ssh_key:
                        success = self._ssh_run_command_with_key(working_ip, ssh_user, stop_cmd, ssh_key)
                    if not success:
                        success = self._ssh_run_command(working_ip, ssh_user, stop_cmd)
                    if not success and ssh_password:
                        success = self._ssh_run_command_with_password(working_ip, ssh_user, stop_cmd, ssh_password)
                    
                    if success:
                        stopped.append(f"VM {vmid}")
                    else:
                        failed.append(f"VM {vmid}")
            
            # Stop containers
            if ctids:
                for ctid in ctids:
                    self.logger.info(f"[HA] Stopping CT {ctid} on {node}...")
                    stop_cmd = f"pct stop {ctid} --timeout 30 2>&1"
                    
                    success = False
                    if ssh_key:
                        success = self._ssh_run_command_with_key(working_ip, ssh_user, stop_cmd, ssh_key)
                    if not success:
                        success = self._ssh_run_command(working_ip, ssh_user, stop_cmd)
                    if not success and ssh_password:
                        success = self._ssh_run_command_with_password(working_ip, ssh_user, stop_cmd, ssh_password)
                    
                    if success:
                        stopped.append(f"CT {ctid}")
                    else:
                        failed.append(f"CT {ctid}")
            
            self.logger.info(f"[HA] Stopped on {node}: {stopped}")
            if failed:
                self.logger.warning(f"[HA] Failed to stop on {node}: {failed}")
            
            return len(failed) == 0
            
        except Exception as e:
            self.logger.error(f"[HA] Error stopping VMs via SSH: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SIMPLE SELF-FENCE AGENT - NS Jan 2026
    # 
    # Ultra-simple split-brain protection:
    # - Each node pings the manager AND the other node
    # - If BOTH unreachable → I'm isolated → stop my VMs
    # - No shared storage needed! Works with LVM, iSCSI, anything.
    # ═══════════════════════════════════════════════════════════════════════════
    
    _SELF_FENCE_AGENT_SCRIPT = '''#!/bin/bash
# PegaProx Self-Fence Agent
# Simple logic: If I can't reach ANYONE, I'm isolated → stop my VMs

MANAGER_IP="__MANAGER_IP__"
OTHER_NODES="__OTHER_NODES__"  # comma-separated list
CHECK_INTERVAL=5
FAIL_THRESHOLD=3
FAIL_COUNT=0

log() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/pegaprox-agent.log
}

can_reach_anyone() {
    # Try manager first
    if ping -c1 -W2 $MANAGER_IP >/dev/null 2>&1; then
        return 0
    fi
    
    # Try other nodes
    IFS=',' read -ra NODES <<< "$OTHER_NODES"
    for node_ip in "${NODES[@]}"; do
        if [ -n "$node_ip" ] && ping -c1 -W2 $node_ip >/dev/null 2>&1; then
            return 0
        fi
    done
    
    return 1
}

stop_all_vms() {
    log "STOPPING ALL VMs AND CONTAINERS!"
    
    # Stop VMs
    for vmid in $(qm list 2>/dev/null | grep running | awk '{print $1}'); do
        log "Stopping VM $vmid"
        qm stop $vmid --timeout 30 2>/dev/null &
    done
    
    # Stop containers
    for ctid in $(pct list 2>/dev/null | grep running | awk '{print $1}'); do
        log "Stopping CT $ctid"
        pct stop $ctid --timeout 30 2>/dev/null &
    done
    
    wait
    log "All VMs/CTs stopped"
}

log "PegaProx Self-Fence Agent starting"
log "Manager: $MANAGER_IP"
log "Other nodes: $OTHER_NODES"
log "Threshold: $FAIL_THRESHOLD failures"

while true; do
    if can_reach_anyone; then
        if [ $FAIL_COUNT -gt 0 ]; then
            log "Network recovered (was at $FAIL_COUNT failures)"
        fi
        FAIL_COUNT=0
    else
        ((FAIL_COUNT++))
        log "WARNING: Cannot reach anyone! Failure count: $FAIL_COUNT/$FAIL_THRESHOLD"
        
        if [ $FAIL_COUNT -ge $FAIL_THRESHOLD ]; then
            log "════════════════════════════════════════════════════════"
            log "ISOLATED! Cannot reach manager OR any other node!"
            log "Self-fencing to prevent split-brain..."
            log "════════════════════════════════════════════════════════"
            stop_all_vms
            
            # Wait for network to recover before resuming checks
            log "Waiting for network recovery..."
            while ! can_reach_anyone; do
                sleep 10
            done
            log "Network recovered! Resuming normal operation."
            FAIL_COUNT=0
        fi
    fi
    
    sleep $CHECK_INTERVAL
done
'''

    def _ha_install_self_fence_agent(self, node_name: str, node_ip: str) -> bool:
        """install self-fence agent on a node via SSH"""
        try:
            # Get manager IP (this PegaProx server)
            manager_ip = self._get_pegaprox_server_ip()
            if not manager_ip:
                self.logger.error(f"[HA] Cannot determine PegaProx server IP!")
                return False
            
            # Get other node IPs
            other_nodes = self._ha_get_other_node_ips(node_name)
            other_nodes_str = ','.join(other_nodes)
            
            self.logger.info(f"[HA] Installing self-fence agent on {node_name}")
            self.logger.info(f"[HA]   Manager IP: {manager_ip}")
            self.logger.info(f"[HA]   Other nodes: {other_nodes_str}")
            
            # Prepare agent script
            agent_script = self._SELF_FENCE_AGENT_SCRIPT
            agent_script = agent_script.replace('__MANAGER_IP__', manager_ip)
            agent_script = agent_script.replace('__OTHER_NODES__', other_nodes_str)
            
            # SSH credentials - try multiple sources
            ssh_user = getattr(self.config, 'ssh_user', None) or 'root'
            ssh_key = getattr(self.config, 'ssh_key_path', None) or getattr(self.config, 'ssh_key', None)
            ssh_password = getattr(self.config, 'ssh_password', None) or self.config.pass_  # Fallback to Proxmox password
            
            self.logger.debug(f"[HA] SSH credentials: user={ssh_user}, has_key={bool(ssh_key)}, has_password={bool(ssh_password)}")
            
            # Create agent script on node
            import base64
            script_b64 = base64.b64encode(agent_script.encode()).decode()
            
            install_cmd = f'''
echo "{script_b64}" | base64 -d > /usr/local/bin/pegaprox-agent.sh
chmod +x /usr/local/bin/pegaprox-agent.sh

cat > /etc/systemd/system/pegaprox-agent.service << 'SERVICEEOF'
[Unit]
Description=PegaProx Self-Fence Agent
After=network.target pve-cluster.service

[Service]
Type=simple
ExecStart=/usr/local/bin/pegaprox-agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable pegaprox-agent.service
systemctl restart pegaprox-agent.service
echo "AGENT_INSTALLED"
'''
            
            # Execute installation - try different methods
            result = None
            
            # 1. Try with SSH key if available
            if result is None and ssh_key:
                self.logger.info(f"[HA] Trying SSH key authentication to {node_ip}...")
                result = self._ssh_run_command_with_key_output(node_ip, ssh_user, install_cmd, ssh_key)
            
            # 2. Try with sshpass (password) if available
            if result is None and ssh_password:
                # Check if sshpass is installed
                import shutil
                if shutil.which('sshpass'):
                    self.logger.info(f"[HA] Trying SSH password authentication to {node_ip}...")
                    result = self._ssh_run_command_with_password_output(node_ip, ssh_user, install_cmd, ssh_password)
                else:
                    self.logger.warning(f"[HA] sshpass not installed - cannot use password auth. Install with: apt install sshpass")
            
            # 3. Try with default SSH (requires pre-configured keys)
            if result is None:
                self.logger.info(f"[HA] Trying default SSH authentication to {node_ip}...")
                result = self._ssh_run_command_output(node_ip, ssh_user, install_cmd)
            
            if result and 'AGENT_INSTALLED' in result:
                self.logger.info(f"[HA] ✓ Self-fence agent installed on {node_name}")
                return True
            else:
                self.logger.error(f"[HA] SSH to {node_ip} failed (key={bool(ssh_key)}, pass={bool(ssh_password)})")
                return False
                
        except Exception as e:
            self.logger.error(f"[HA] Error installing self-fence agent on {node_name}: {e}")
            return False
    
    def _get_pegaprox_server_ip(self) -> str:
        """Get the IP address of this PegaProx server that nodes can reach"""
        import socket
        
        # Try to get the IP we use to connect to the cluster
        try:
            host = self.current_host or self.config.host
            # Create a socket to the cluster to find our outgoing IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, 8006))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            pass
        
        # Fallback: try to get default interface IP
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except:
            return ''
    
    def _ha_get_other_node_ips(self, exclude_node: str) -> list:
        """Get IP addresses of all nodes except the specified one"""
        other_ips = []
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code == 200:
                nodes_data = resp.json().get('data', [])
                self.logger.debug(f"[HA] Found {len(nodes_data)} nodes in cluster")
                
                for node in nodes_data:
                    node_name = node.get('node', '')
                    self.logger.debug(f"[HA] Checking node: {node_name} (exclude: {exclude_node})")
                    
                    # Case-insensitive comparison - NS Jan 2026
                    if node_name and node_name.lower() != exclude_node.lower():
                        # Use existing _ha_get_node_ip function
                        node_ip = self._ha_get_node_ip(node_name)
                        
                        if node_ip:
                            other_ips.append(node_ip)
                            self.logger.info(f"[HA] Found other node: {node_name} -> {node_ip}")
                        else:
                            self.logger.warning(f"[HA] Could not find IP for node: {node_name}")
                            
        except Exception as e:
            self.logger.error(f"[HA] Error getting other node IPs: {e}")
        
        return other_ips
    
    def _ha_install_self_fence_on_all_nodes(self) -> dict:
        """install self-fence agent on all cluster nodes, returns {node: success} dict"""
        results = {}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                self.logger.error("[HA] Cannot get node list from cluster")
                return results
            
            nodes = resp.json().get('data', [])
            self.logger.info(f"[HA] Installing self-fence agent on {len(nodes)} nodes...")
            
            for node in nodes:
                node_name = node.get('node', '')
                if not node_name:
                    continue
                
                # Get node IP
                node_ip = self._ha_get_node_ip(node_name)
                if not node_ip:
                    self.logger.warning(f"[HA] Cannot determine IP for node {node_name}")
                    results[node_name] = False
                    continue
                
                # Install agent
                success = self._ha_install_self_fence_agent(node_name, node_ip)
                results[node_name] = success
            
            success_count = sum(1 for v in results.values() if v)
            self.logger.info(f"[HA] Self-fence agent installation complete: {success_count}/{len(results)}")
            
        except Exception as e:
            self.logger.error(f"[HA] Error installing self-fence agents: {e}")
        
        return results
    
    def _ha_uninstall_self_fence_on_all_nodes(self) -> dict:
        """uninstall self-fence agent from all cluster nodes, returns {node: success} dict"""
        results = {}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                self.logger.error("[HA] Cannot get node list from cluster")
                return results
            
            nodes = resp.json().get('data', [])
            self.logger.info(f"[HA] Uninstalling self-fence agent from {len(nodes)} nodes...")
            
            for node in nodes:
                node_name = node.get('node', '')
                if not node_name:
                    continue
                
                # Get node IP
                node_ip = self._ha_get_node_ip(node_name)
                if not node_ip:
                    self.logger.warning(f"[HA] Cannot determine IP for node {node_name}")
                    results[node_name] = False
                    continue
                
                # Uninstall agent
                success = self._ha_uninstall_self_fence_agent(node_name, node_ip)
                results[node_name] = success
            
            success_count = sum(1 for v in results.values() if v)
            self.logger.info(f"[HA] Self-fence agent uninstallation complete: {success_count}/{len(results)}")
            
        except Exception as e:
            self.logger.error(f"[HA] Error uninstalling self-fence agents: {e}")
        
        return results
    
    def _ha_uninstall_self_fence_agent(self, node_name: str, node_ip: str) -> bool:
        """uninstall self-fence agent from a single node via SSH"""
        try:
            self.logger.info(f"[HA] Uninstalling self-fence agent from {node_name}")
            
            # SSH credentials - try multiple sources (same as install)
            ssh_user = getattr(self.config, 'ssh_user', None) or 'root'
            ssh_key = getattr(self.config, 'ssh_key_path', None) or getattr(self.config, 'ssh_key', None)
            ssh_password = getattr(self.config, 'ssh_password', None) or self.config.pass_
            
            uninstall_cmd = '''
systemctl stop pegaprox-agent.service 2>/dev/null || true
systemctl disable pegaprox-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/pegaprox-agent.service
rm -f /usr/local/bin/pegaprox-agent.sh
systemctl daemon-reload
echo "AGENT_UNINSTALLED"
'''
            
            # Execute uninstallation - try different methods
            result = None
            
            if result is None and ssh_key:
                result = self._ssh_run_command_with_key_output(node_ip, ssh_user, uninstall_cmd, ssh_key)
            if result is None and ssh_password:
                result = self._ssh_run_command_with_password_output(node_ip, ssh_user, uninstall_cmd, ssh_password)
            if result is None:
                result = self._ssh_run_command_output(node_ip, ssh_user, uninstall_cmd)
            
            if result and 'AGENT_UNINSTALLED' in result:
                self.logger.info(f"[HA] ✓ Self-fence agent uninstalled from {node_name}")
                return True
            else:
                self.logger.error(f"[HA] ✗ Failed to uninstall agent from {node_name}: {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"[HA] Error uninstalling self-fence agent from {node_name}: {e}")
            return False
    
    def _ha_stop_self_fence_agents(self):
        """Stop (but don't uninstall) self-fence agents on all nodes
        
        Used when HA is disabled to prevent agents from running without manager
        """
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                return
            
            for node in resp.json().get('data', []):
                node_name = node.get('node', '')
                node_ip = self._ha_get_node_ip(node_name) if node_name else None
                
                if node_ip:
                    ssh_user = getattr(self.config, 'ssh_user', None) or 'root'
                    ssh_key = getattr(self.config, 'ssh_key_path', None) or getattr(self.config, 'ssh_key', None)
                    ssh_password = getattr(self.config, 'ssh_password', None) or self.config.pass_
                    
                    stop_cmd = 'systemctl stop pegaprox-agent.service 2>/dev/null || true'
                    
                    result = None
                    if ssh_key:
                        result = self._ssh_run_command_with_key_output(node_ip, ssh_user, stop_cmd, ssh_key)
                    if result is None and ssh_password:
                        result = self._ssh_run_command_with_password_output(node_ip, ssh_user, stop_cmd, ssh_password)
                    if result is None:
                        self._ssh_run_command_output(node_ip, ssh_user, stop_cmd)
                        
                    self.logger.info(f"[HA] Stopped self-fence agent on {node_name}")
                    
        except Exception as e:
            self.logger.error(f"[HA] Error stopping self-fence agents: {e}")
    
    def _ha_start_self_fence_agents(self):
        """Start self-fence agents on all nodes
        
        Used when HA is enabled and agents were previously installed
        """
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                return
            
            for node in resp.json().get('data', []):
                node_name = node.get('node', '')
                node_ip = self._ha_get_node_ip(node_name) if node_name else None
                
                if node_ip:
                    ssh_user = getattr(self.config, 'ssh_user', None) or 'root'
                    ssh_key = getattr(self.config, 'ssh_key_path', None) or getattr(self.config, 'ssh_key', None)
                    ssh_password = getattr(self.config, 'ssh_password', None) or self.config.pass_
                    
                    start_cmd = 'systemctl start pegaprox-agent.service 2>/dev/null || true'
                    
                    result = None
                    if ssh_key:
                        result = self._ssh_run_command_with_key_output(node_ip, ssh_user, start_cmd, ssh_key)
                    if result is None and ssh_password:
                        result = self._ssh_run_command_with_password_output(node_ip, ssh_user, start_cmd, ssh_password)
                    if result is None:
                        self._ssh_run_command_output(node_ip, ssh_user, start_cmd)
                        
                    self.logger.info(f"[HA] Started self-fence agent on {node_name}")
                    
        except Exception as e:
            self.logger.error(f"[HA] Error starting self-fence agents: {e}")
    
    def _ha_discover_shared_storages(self, force_refresh: bool = False) -> list:
        """Automatically discover all shared storages in the cluster
        
        Queries Proxmox API for storages and filters for:
        - shared: 1 (accessible from all nodes)
        - type: nfs, cephfs, glusterfs (filesystem-based)
        
        Also detects block-based storages (LVM, iSCSI, RBD) to warn user.
        
        Results are cached to avoid repeated API calls.
        
        Returns list of dicts with storage info:
        [{'name': 'cephfs', 'type': 'cephfs', 'path': '/mnt/pve/cephfs', 'shared': True, 'is_filesystem': True}, ...]
        """
        # Return cached results if available and not forcing refresh
        if not force_refresh and hasattr(self, '_cached_shared_storages') and self._cached_shared_storages:
            return self._cached_shared_storages
        
        storages = []
        block_storages = []  # Track block-based storages for warning
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/storage"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                self.logger.warning("[HA] Cannot query storages from Proxmox API")
                return storages
            
            for storage in resp.json().get('data', []):
                # Only interested in shared storages
                if not storage.get('shared'):
                    continue
                
                storage_type = storage.get('type', '')
                storage_name = storage.get('storage', '')
                
                # Determine the mount path based on storage type
                mount_path = None
                
                if storage_type == 'nfs':
                    # NFS: path is directly provided or mounted at /mnt/pve/<name>
                    mount_path = storage.get('path') or f"/mnt/pve/{storage_name}"
                    
                elif storage_type == 'cephfs':
                    # CephFS: always mounted at /mnt/pve/<name>
                    mount_path = f"/mnt/pve/{storage_name}"
                    
                elif storage_type == 'glusterfs':
                    # GlusterFS: mounted at /mnt/pve/<name>
                    mount_path = f"/mnt/pve/{storage_name}"
                    
                elif storage_type == 'dir' and storage.get('shared'):
                    # Shared directory (might be NFS mounted elsewhere)
                    mount_path = storage.get('path')
                    
                elif storage_type == 'pbs':
                    # Proxmox Backup Server - not a filesystem, skip
                    continue
                    
                elif storage_type in ['rbd', 'iscsi', 'zfspool', 'lvm', 'lvmthin']:
                    # Block-based storage - track for warning but can't use for heartbeats
                    block_storages.append({
                        'name': storage_name,
                        'type': storage_type,
                        'shared': True,
                        'is_filesystem': False,
                    })
                    self.logger.debug(f"[HA] Found shared BLOCK storage (not usable for heartbeats): {storage_name} ({storage_type})")
                    continue
                
                if mount_path:
                    storages.append({
                        'name': storage_name,
                        'type': storage_type,
                        'path': mount_path,
                        'shared': True,
                        'is_filesystem': True,
                        'content': storage.get('content', ''),
                        'enabled': storage.get('enabled', True) if storage.get('disable') != 1 else False
                    })
                    self.logger.debug(f"[HA] Found shared filesystem storage: {storage_name} ({storage_type}) at {mount_path}")
            
            self.logger.info(f"[HA] Discovered {len(storages)} filesystem storages, {len(block_storages)} block storages")
            
            # Warn if only block storage available
            if not storages and block_storages:
                self.logger.warning(f"[HA] ════════════════════════════════════════════════════════")
                self.logger.warning(f"[HA] ⚠️ Only BLOCK storage found (LVM/iSCSI/RBD)!")
                self.logger.warning(f"[HA] ⚠️ Block storage cannot store heartbeat files.")
                self.logger.warning(f"[HA] ⚠️ Add a small NFS share for full protection.")
                self.logger.warning(f"[HA] ════════════════════════════════════════════════════════")
            
        except Exception as e:
            self.logger.error(f"[HA] Error discovering shared storages: {e}")
        
        # Cache results
        self._cached_shared_storages = storages
        self._cached_block_storages = block_storages
        return storages
    
    def _ha_get_best_shared_storage_path(self) -> str:
        """Automatically select the best shared storage for heartbeats
        
        Priority:
        1. CephFS (built-in, fast, reliable)
        2. GlusterFS (distributed)
        3. NFS (common, well-supported)
        4. Any other shared filesystem
        
        Returns the mount path or empty string if none found
        """
        storages = self._ha_discover_shared_storages()
        
        if not storages:
            self.logger.warning("[HA] No shared filesystem storages found!")
            return ''
        
        # Sort by preference
        type_priority = {'cephfs': 1, 'glusterfs': 2, 'nfs': 3, 'dir': 4}
        storages.sort(key=lambda s: type_priority.get(s['type'], 99))
        
        best = storages[0]
        self.logger.info(f"[HA] Selected best shared storage: {best['name']} ({best['type']}) at {best['path']}")
        
        return best['path']
    
    def _ha_auto_setup_split_brain_protection(self) -> bool:
        """Fully automatic split-brain protection setup
        
        1. Discovers shared storages
        2. Selects the best one
        3. Installs node agents
        4. Enables storage heartbeat
        
        Returns True if setup successful
        """
        self.logger.info("[HA] ═══════════════════════════════════════════════════════")
        self.logger.info("[HA] AUTOMATIC SPLIT-BRAIN PROTECTION SETUP")
        self.logger.info("[HA] ═══════════════════════════════════════════════════════")
        
        # Step 1: Find best shared storage
        storage_path = self._ha_get_best_shared_storage_path()
        
        if not storage_path:
            self.logger.warning("[HA] No shared storage found - falling back to SSH-only mode")
            self.logger.warning("[HA] ⚠️ This is NOT safe for dual-network setups!")
            return False
        
        # Step 2: Configure storage heartbeat
        self.ha_config['storage_heartbeat_enabled'] = True
        self.ha_config['storage_heartbeat_path'] = storage_path
        self.ha_config['dual_network_mode'] = True
        self.ha_config['poison_pill_enabled'] = True
        
        # Step 3: Install agents on all nodes
        self.logger.info(f"[HA] Installing node agents with storage path: {storage_path}")
        results = self._ha_install_agents_on_all_nodes()
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        if success_count == total_count:
            self.logger.info(f"[HA] ✓ All {total_count} node agents installed successfully!")
            return True
        elif success_count > 0:
            self.logger.warning(f"[HA] ⚠️ {success_count}/{total_count} node agents installed")
            return True
        else:
            self.logger.error("[HA] ✗ Failed to install any node agents!")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATIC NODE AGENT INSTALLATION - NS Jan 2026
    # 
    # For dual-network setups where server network and storage network are separate.
    # The agent runs on each node and communicates via the STORAGE network.
    # This survives server network failures!
    #
    # The agent is automatically installed via SSH when dual_network_mode is enabled.
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Minimal node agent script - embedded as string for auto-deployment
    _NODE_AGENT_SCRIPT = '''#!/bin/bash
# PegaProx Node Agent - Auto-installed for Dual-Network Split-Brain Protection
# This agent communicates via STORAGE network, not server network!

STORAGE_PATH="__STORAGE_PATH__"
HEARTBEAT_INTERVAL=5
NODE_NAME=$(hostname)
PEGAPROX_DIR="${STORAGE_PATH}/.pegaprox"
HEARTBEAT_FILE="${PEGAPROX_DIR}/heartbeat_node_${NODE_NAME}"
POISON_FILE="${PEGAPROX_DIR}/poison_${NODE_NAME}"
POISON_ACK_FILE="${PEGAPROX_DIR}/poison_ack_${NODE_NAME}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /var/log/pegaprox-agent.log; }

write_heartbeat() {
    mkdir -p "$PEGAPROX_DIR" 2>/dev/null
    local vms=$(qm list 2>/dev/null | grep running | awk '{print $1}' | tr '\\n' ',')
    local cts=$(pct list 2>/dev/null | grep running | awk '{print $1}' | tr '\\n' ',')
    echo "{\\"timestamp\\":\\"$(date -Iseconds)\\",\\"node\\":\\"$NODE_NAME\\",\\"vms\\":\\"$vms\\",\\"cts\\":\\"$cts\\"}" > "$HEARTBEAT_FILE"
}

check_poison() {
    if [ -f "$POISON_FILE" ]; then
        log "POISON PILL DETECTED! Stopping all VMs..."
        for vmid in $(qm list 2>/dev/null | grep running | awk '{print $1}'); do
            log "Stopping VM $vmid"
            qm stop $vmid --timeout 30 2>/dev/null &
        done
        for ctid in $(pct list 2>/dev/null | grep running | awk '{print $1}'); do
            log "Stopping CT $ctid"
            pct stop $ctid --timeout 30 2>/dev/null &
        done
        wait
        echo "{\\"timestamp\\":\\"$(date -Iseconds)\\",\\"node\\":\\"$NODE_NAME\\",\\"vms_stopped\\":true}" > "$POISON_ACK_FILE"
        rm -f "$POISON_FILE"
        log "All VMs stopped, poison acknowledged"
    fi
}

log "PegaProx Node Agent starting (storage: $STORAGE_PATH)"
while true; do
    write_heartbeat
    check_poison
    sleep $HEARTBEAT_INTERVAL
done
'''

    _NODE_AGENT_SERVICE = '''[Unit]
Description=PegaProx Node Agent (Dual-Network Split-Brain Protection)
After=network.target pve-cluster.service
Wants=pve-cluster.service

[Service]
Type=simple
ExecStart=/usr/local/bin/pegaprox-agent.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
'''

    def _ha_install_node_agent(self, node: str) -> bool:
        """Auto-install the node agent on a Proxmox node via SSH
        
        This is called automatically when dual_network_mode is enabled.
        The agent writes heartbeats to shared storage and responds to poison pills.
        """
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            self.logger.error(f"[HA] Cannot install agent: storage_heartbeat_path not configured!")
            return False
        
        try:
            node_ip = self._ha_get_node_ip(node)
            if not node_ip:
                self.logger.error(f"[HA] Cannot get IP for node {node}")
                return False
            
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')
            
            self.logger.info(f"[HA] 🔧 Installing node agent on {node} ({node_ip})...")
            
            # Prepare script with actual storage path
            agent_script = self._NODE_AGENT_SCRIPT.replace('__STORAGE_PATH__', storage_path)
            
            # Create the script file on the node
            # Use base64 to avoid escaping issues
            import base64
            script_b64 = base64.b64encode(agent_script.encode()).decode()
            service_b64 = base64.b64encode(self._NODE_AGENT_SERVICE.encode()).decode()
            
            install_cmd = f'''
echo "{script_b64}" | base64 -d > /usr/local/bin/pegaprox-agent.sh && 
chmod +x /usr/local/bin/pegaprox-agent.sh && 
echo "{service_b64}" | base64 -d > /etc/systemd/system/pegaprox-agent.service && 
systemctl daemon-reload && 
systemctl enable pegaprox-agent && 
systemctl restart pegaprox-agent && 
echo "AGENT_INSTALLED_OK"
'''
            
            success = False
            if ssh_key:
                output = self._ssh_run_command_with_key_output(node_ip, ssh_user, install_cmd, ssh_key)
                success = output and 'AGENT_INSTALLED_OK' in output
            
            if not success:
                output = self._ssh_run_command_output(node_ip, ssh_user, install_cmd)
                success = output and 'AGENT_INSTALLED_OK' in output
            
            if not success and ssh_password:
                output = self._ssh_run_command_with_password_output(node_ip, ssh_user, install_cmd, ssh_password)
                success = output and 'AGENT_INSTALLED_OK' in output
            
            if success:
                self.logger.info(f"[HA] ✓ Node agent installed successfully on {node}")
                self.ha_config['node_agent_installed'][node] = True
                return True
            else:
                self.logger.error(f"[HA] ✗ Failed to install node agent on {node}")
                return False
                
        except Exception as e:
            self.logger.error(f"[HA] Error installing node agent on {node}: {e}")
            return False
    
    def _ha_install_agents_on_all_nodes(self) -> dict:
        """Install node agents on all nodes in the cluster
        
        Returns dict: {node_name: success_bool}
        """
        results = {}
        
        # Get all nodes
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes"
            resp = self._create_session().get(url, timeout=10)
            
            if resp.status_code != 200:
                self.logger.error("[HA] Cannot get node list for agent installation")
                return results
            
            nodes = resp.json().get('data', [])
            
            self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
            self.logger.info(f"[HA] INSTALLING NODE AGENTS ON {len(nodes)} NODES")
            self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
            
            for node in nodes:
                node_name = node.get('node')
                success = self._ha_install_node_agent(node_name)
                results[node_name] = success
            
            success_count = sum(1 for v in results.values() if v)
            self.logger.info(f"[HA] Agent installation complete: {success_count}/{len(nodes)} successful")
            
        except Exception as e:
            self.logger.error(f"[HA] Error during agent installation: {e}")
        
        return results
    
    def _ha_check_node_agent_heartbeat(self, node: str) -> dict:
        """check if node agent is writing heartbeats to storage (works even if server network is down)"""
        result = {'alive': False, 'age_seconds': None, 'running_vms': [], 'running_cts': []}
        
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return result
        
        heartbeat_file = os.path.join(storage_path, '.pegaprox', f'heartbeat_node_{node}')
        timeout = self.ha_config.get('storage_heartbeat_timeout', 30)
        
        try:
            if os.path.exists(heartbeat_file):
                mtime = datetime.fromtimestamp(os.path.getmtime(heartbeat_file))
                age = (datetime.now() - mtime).total_seconds()
                result['age_seconds'] = age
                result['alive'] = age < timeout
                
                # Read heartbeat content with validation
                try:
                    with open(heartbeat_file, 'r') as f:
                        data = json.load(f)
                    if not isinstance(data, dict):
                        self.logger.warning(f"[HA] Invalid heartbeat format for {node}: expected dict, got {type(data).__name__}")
                    else:
                        if data.get('vms'):
                            result['running_vms'] = [v.strip() for v in data['vms'].split(',') if v.strip()]
                        if data.get('cts'):
                            result['running_cts'] = [c.strip() for c in data['cts'].split(',') if c.strip()]
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.warning(f"[HA] Corrupt heartbeat file for {node}: {e}")
                
                self.logger.debug(f"[HA] Node {node} storage heartbeat: age={age:.1f}s, alive={result['alive']}")
            else:
                self.logger.debug(f"[HA] No storage heartbeat file for {node}")
                
        except Exception as e:
            self.logger.error(f"[HA] Error reading storage heartbeat for {node}: {e}")
        
        return result
    
    def _ssh_run_command_output(self, host: str, user: str, command: str, timeout: int = 30) -> str:
        """Run SSH command and return output - HA PRIORITY (no rate limiting)
        
        NS: Jan 2026 - HA status checks bypass semaphore for immediate execution
        """
        _ssh_track_connection('ha', +1)
        
        try:
            ct = self.ha_config.get('ssh_connect_timeout', 10)
            result = subprocess.run(
                ['ssh', '-o', f'ConnectTimeout={ct}', '-o', 'StrictHostKeyChecking=no',
                 '-o', 'BatchMode=yes', f'{user}@{host}', command],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return result.stdout
            self.logger.debug(f"[SSH] Command failed on {host}: {result.stderr[:200] if result.stderr else 'no error output'}")
            return None
        except subprocess.TimeoutExpired:
            self.logger.debug(f"[SSH] Command timed out on {host}")
            return None
        except Exception as e:
            self.logger.debug(f"[SSH] Exception on {host}: {e}")
            return None
        finally:
            _ssh_track_connection('ha', -1)
    
    def _ssh_run_command_with_key_output(self, host: str, user: str, command: str, key: str, timeout: int = 30) -> str:
        """Run SSH command with key and return output - HA PRIORITY (no rate limiting)
        
        NS: Jan 2026 - HA operations bypass semaphore
        """
        _ssh_track_connection('ha', +1)
        
        try:
            import tempfile

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
                f.write(key)
                key_file = f.name
            os.chmod(key_file, 0o600)
            
            ct = self.ha_config.get('ssh_connect_timeout', 10)
            try:
                result = subprocess.run(
                    ['ssh', '-o', f'ConnectTimeout={ct}', '-o', 'StrictHostKeyChecking=no',
                     '-i', key_file, f'{user}@{host}', command],
                    capture_output=True, text=True, timeout=timeout
                )
                if result.returncode == 0:
                    return result.stdout
                self.logger.debug(f"[SSH] Key auth failed on {host}: {result.stderr[:200] if result.stderr else 'no error output'}")
                return None
            finally:
                os.unlink(key_file)
        except subprocess.TimeoutExpired:
            self.logger.debug(f"[SSH] Key command timed out on {host}")
            return None
        except Exception as e:
            self.logger.debug(f"[SSH] Key exception on {host}: {e}")
            return None
        finally:
            _ssh_track_connection('ha', -1)
    
    def _ssh_run_command_with_password_output(self, host: str, user: str, command: str, password: str, timeout: int = 30) -> str:
        """Run SSH command with password and return output - HA PRIORITY (no rate limiting)
        
        NS: Jan 2026 - HA operations bypass semaphore
        """
        _ssh_track_connection('ha', +1)
        
        try:
            env = os.environ.copy()
            env['SSHPASS'] = password
            
            ct = self.ha_config.get('ssh_connect_timeout', 10)
            result = subprocess.run(
                ['sshpass', '-e', 'ssh', '-o', f'ConnectTimeout={ct}', '-o', 'StrictHostKeyChecking=no',
                 f'{user}@{host}', command],
                capture_output=True, text=True, timeout=timeout, env=env
            )
            if result.returncode == 0:
                return result.stdout
            self.logger.debug(f"[SSH] Password auth failed on {host}: {result.stderr[:200] if result.stderr else 'no error output'}")
            return None
        except FileNotFoundError:
            self.logger.debug(f"[SSH] sshpass not installed - cannot use password auth")
            return None
        except subprocess.TimeoutExpired:
            self.logger.debug(f"[SSH] Password command timed out on {host}")
            return None
        except Exception as e:
            self.logger.debug(f"[SSH] Password exception on {host}: {e}")
            return None
        finally:
            _ssh_track_connection('ha', -1)
    
    # Legacy storage-based functions kept for advanced users who want extra safety
    def _ha_storage_heartbeat_init(self):
        """Initialize storage-based heartbeat system"""
        if not self.ha_config.get('storage_heartbeat_enabled'):
            return
        
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            self.logger.warning("[HA] Storage heartbeat enabled but no path configured!")
            return
        
        # Create .pegaprox directory on shared storage
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        try:
            os.makedirs(heartbeat_dir, exist_ok=True)
            self.logger.info(f"[HA] Storage heartbeat directory: {heartbeat_dir}")
        except Exception as e:
            self.logger.error(f"[HA] Cannot create heartbeat directory: {e}")
            return
        
        # Start heartbeat writer thread
        self.ha_heartbeat_stop.clear()
        self.ha_heartbeat_thread = threading.Thread(
            target=self._ha_storage_heartbeat_writer,
            daemon=True,
            name=f"HA-Heartbeat-{self.config.name}"
        )
        self.ha_heartbeat_thread.start()
        self.logger.info("[HA] Storage heartbeat writer started")
    
    def _ha_storage_heartbeat_writer(self):
        """Background thread that writes heartbeats to shared storage"""
        storage_path = self.ha_config.get('storage_heartbeat_path')
        interval = self.ha_config.get('storage_heartbeat_interval', 5)
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        
        while not self.ha_heartbeat_stop.is_set():
            try:
                # Write heartbeat for this PegaProx instance
                heartbeat_file = os.path.join(heartbeat_dir, f'heartbeat_pegaprox_{self.id}')
                heartbeat_data = {
                    'timestamp': datetime.now().isoformat(),
                    'cluster_id': self.id,
                    'cluster_name': self.config.name,
                    'connected_to': self.current_host,
                    'ha_enabled': self.config.ha_enabled,
                    'nodes_status': {k: v.get('status') for k, v in self.ha_node_status.items()}
                }
                
                with open(heartbeat_file, 'w') as f:
                    import json
                    json.dump(heartbeat_data, f)
                
                self.ha_last_heartbeat_write = datetime.now()
                
                # Also check for poison pills targeting our nodes
                self._ha_check_poison_pills()
                
            except Exception as e:
                self.logger.error(f"[HA] Heartbeat write error: {e}")
            
            self.ha_heartbeat_stop.wait(interval)
    
    def _ha_check_storage_heartbeat(self, node: str) -> dict:
        """check storage heartbeat of another node, returns {alive, last_seen, age_seconds}"""
        storage_path = self.ha_config.get('storage_heartbeat_path')
        timeout = self.ha_config.get('storage_heartbeat_timeout', 30)
        
        if not storage_path:
            return {'alive': None, 'last_seen': None, 'age_seconds': None, 'error': 'No storage path configured'}
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        
        # Look for heartbeat files from Proxmox nodes (written by pvestatd or our agent)
        # Also look for VM status files
        result = {'alive': None, 'last_seen': None, 'age_seconds': None}
        
        try:
            # Check node-specific heartbeat (if we install an agent on nodes)
            node_heartbeat = os.path.join(heartbeat_dir, f'heartbeat_node_{node}')
            if os.path.exists(node_heartbeat):
                mtime = datetime.fromtimestamp(os.path.getmtime(node_heartbeat))
                age = (datetime.now() - mtime).total_seconds()
                result['last_seen'] = mtime
                result['age_seconds'] = age
                result['alive'] = age < timeout
                
                self.logger.debug(f"[HA] Node {node} heartbeat age: {age:.1f}s (timeout: {timeout}s)")
                return result
            
            # Fallback: Check if node has written to shared storage recently
            # This works with NFS/Ceph where we can see file mtimes
            node_status_file = os.path.join(heartbeat_dir, f'status_{node}')
            if os.path.exists(node_status_file):
                mtime = datetime.fromtimestamp(os.path.getmtime(node_status_file))
                age = (datetime.now() - mtime).total_seconds()
                result['last_seen'] = mtime
                result['age_seconds'] = age
                result['alive'] = age < timeout
                return result
            
            # No heartbeat found - node hasn't registered yet or is dead
            result['error'] = 'No heartbeat file found'
            result['alive'] = False
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"[HA] Error checking storage heartbeat for {node}: {e}")
        
        return result
    
    def _ha_write_poison_pill(self, target_node: str, reason: str) -> bool:
        """write poison pill to shared storage, telling target node to stop VMs"""
        if not self.ha_config.get('poison_pill_enabled', True):
            return False
        
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return False
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        poison_file = os.path.join(heartbeat_dir, f'poison_{target_node}')
        
        try:
            poison_data = {
                'timestamp': datetime.now().isoformat(),
                'target_node': target_node,
                'reason': reason,
                'issued_by': f'pegaprox_{self.id}',
                'action_required': 'STOP_ALL_VMS',
                'recovery_will_start_after': (datetime.now() + timedelta(seconds=60)).isoformat()
            }
            
            with open(poison_file, 'w') as f:
                import json
                json.dump(poison_data, f)
            
            self.logger.warning(f"[HA] ☠️ POISON PILL written for {target_node}: {reason}")
            self.logger.info(f"[HA] If {target_node} is alive and can see storage, it MUST stop its VMs")
            
            return True
            
        except Exception as e:
            self.logger.error(f"[HA] Failed to write poison pill: {e}")
            return False
    
    def _ha_check_poison_pills(self):
        """Check if there are poison pills targeting nodes in our cluster
        
        This is called regularly by the heartbeat thread.
        If we find a poison pill for a node we're connected to, we need to act!
        """
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        
        try:
            # Check for poison pills for any node in our cluster
            for node_name in list(self.ha_node_status.keys()):
                poison_file = os.path.join(heartbeat_dir, f'poison_{node_name}')
                
                if os.path.exists(poison_file):
                    with open(poison_file, 'r') as f:
                        import json
                        poison_data = json.load(f)
                    
                    # Check if poison pill is recent (< 5 minutes old)
                    poison_time = datetime.fromisoformat(poison_data['timestamp'])
                    age = (datetime.now() - poison_time).total_seconds()
                    
                    if age < 300:  # 5 minutes
                        self.logger.critical(f"[HA] ☠️ POISON PILL DETECTED for {node_name}!")
                        self.logger.critical(f"[HA] Reason: {poison_data.get('reason')}")
                        self.logger.critical(f"[HA] Issued by: {poison_data.get('issued_by')}")
                        
                        # If we're connected to this node, we should NOT start VMs on it
                        if self.current_host and node_name in self.current_host:
                            self.logger.critical(f"[HA] We are connected to poisoned node! Switching connection...")
                            # Don't start new VMs, let the other PegaProx instance handle recovery
                    
        except Exception as e:
            self.logger.error(f"[HA] Error checking poison pills: {e}")
    
    def _ha_wait_for_poison_ack(self, target_node: str, timeout: int = 60) -> bool:
        """wait for target node to ack the poison pill (or timeout)"""
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return True  # Can't check, proceed
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        ack_file = os.path.join(heartbeat_dir, f'poison_ack_{target_node}')
        
        self.logger.info(f"[HA] Waiting up to {timeout}s for poison acknowledgment from {target_node}...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if os.path.exists(ack_file):
                    with open(ack_file, 'r') as f:
                        ack_data = json.load(f)
                    
                    if ack_data.get('vms_stopped'):
                        self.logger.info(f"[HA] ✓ Received poison acknowledgment from {target_node}")
                        self.logger.info(f"[HA]   VMs stopped: {ack_data.get('stopped_vms', [])}")
                        
                        # Clean up poison files individually
                        poison_file = os.path.join(heartbeat_dir, f'poison_{target_node}')
                        for fpath in [poison_file, ack_file]:
                            try:
                                if os.path.exists(fpath):
                                    os.remove(fpath)
                            except OSError as e:
                                self.logger.warning(f"[HA] Could not remove {fpath}: {e}")
                        
                        return True
                
                # Check if node heartbeat is still active (node is alive but ignoring poison)
                heartbeat = self._ha_check_storage_heartbeat(target_node)
                if heartbeat.get('alive') and heartbeat.get('age_seconds', 999) < 10:
                    self.logger.warning(f"[HA] ⚠ Node {target_node} is STILL ALIVE and writing heartbeats!")
                    self.logger.warning(f"[HA] This could indicate split-brain risk!")
                    
            except Exception as e:
                self.logger.error(f"[HA] Error checking poison ack: {e}")
            
            time.sleep(2)
        
        self.logger.warning(f"[HA] ⚠ Poison acknowledgment timeout for {target_node}")
        
        # Final check: is the node still writing heartbeats?
        heartbeat = self._ha_check_storage_heartbeat(target_node)
        if heartbeat.get('alive'):
            self.logger.error(f"[HA] ✗ DANGER: Node {target_node} heartbeat still active after poison!")
            self.logger.error(f"[HA] ✗ ABORTING RECOVERY to prevent split-brain!")
            return False
        
        self.logger.info(f"[HA] Node {target_node} heartbeat is stale - safe to proceed")
        return True
    
    def _ha_acquire_recovery_lock(self, failed_node: str) -> bool:
        """Try to acquire a distributed lock for recovery
        
        Only one PegaProx instance should perform recovery at a time.
        This prevents multiple recovery attempts from different sources.
        """
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return True  # No storage path, can't lock
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        lock_file = os.path.join(heartbeat_dir, f'recovery_lock_{failed_node}')
        
        try:
            # Check if lock exists and is recent
            if os.path.exists(lock_file):
                mtime = datetime.fromtimestamp(os.path.getmtime(lock_file))
                age = (datetime.now() - mtime).total_seconds()
                
                if age < 300:  # Lock valid for 5 minutes
                    with open(lock_file, 'r') as f:
                        import json
                        lock_data = json.load(f)
                    
                    if lock_data.get('holder') != f'pegaprox_{self.id}':
                        self.logger.warning(f"[HA] Recovery lock held by {lock_data.get('holder')}")
                        return False
            
            # Acquire lock
            lock_data = {
                'timestamp': datetime.now().isoformat(),
                'holder': f'pegaprox_{self.id}',
                'target_node': failed_node,
                'cluster': self.config.name
            }
            
            with open(lock_file, 'w') as f:
                import json
                json.dump(lock_data, f)
            
            self.logger.info(f"[HA] ✓ Acquired recovery lock for {failed_node}")
            return True
            
        except Exception as e:
            self.logger.error(f"[HA] Error acquiring recovery lock: {e}")
            return False
    
    def _ha_release_recovery_lock(self, failed_node: str):
        """Release the recovery lock"""
        storage_path = self.ha_config.get('storage_heartbeat_path')
        if not storage_path:
            return
        
        heartbeat_dir = os.path.join(storage_path, '.pegaprox')
        lock_file = os.path.join(heartbeat_dir, f'recovery_lock_{failed_node}')
        
        try:
            if os.path.exists(lock_file):
                os.remove(lock_file)
                self.logger.info(f"[HA] Released recovery lock for {failed_node}")
        except Exception as e:
            self.logger.error(f"[HA] Error releasing recovery lock: {e}")
    
    def _ha_try_force_quorum(self, target_node: str) -> bool:
        """Force quorum on the surviving node in a 2-node cluster
        
        This runs: pvecm expected 1
        Which tells corosync to accept 1 node as quorum.
        
        Uses the cluster's existing credentials (same as Proxmox API login).
        """
        self.logger.warning(f"[HA] ════════════════════════════════════════════════════════")
        self.logger.warning(f"[HA] FORCING QUORUM ON {target_node}")
        self.logger.warning(f"[HA] ════════════════════════════════════════════════════════")
        
        try:
            # Get target node IP
            node_ip = self._ha_get_node_ip(target_node)
            
            if not node_ip:
                self.logger.error(f"[HA] Cannot determine IP for {target_node}")
                return False
            
            self.logger.info(f"[HA] Target node IP: {node_ip}")
            
            # Use cluster credentials - same as Proxmox API login
            # User format is usually "root@pam" - extract just the username
            api_user = self.config.user  # e.g. "root@pam"
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')  # SSH private key from cluster config
            
            self.logger.info(f"[HA] Using cluster credentials (user: {ssh_user})")
            
            # Method 1: Try SSH with configured key first (most secure)
            if ssh_key:
                self.logger.info(f"[HA] Trying SSH with configured key...")
                if self._ssh_run_command_with_key(node_ip, ssh_user, 'pvecm expected 1', ssh_key):
                    return True
            
            # Method 2: Try passwordless SSH (if system keys are set up)
            if self._ssh_run_command(node_ip, ssh_user, 'pvecm expected 1'):
                return True
            
            # Method 3: Try SSH with password (using sshpass - secure env var method)
            if ssh_password:
                if self._ssh_run_command_with_password(node_ip, ssh_user, 'pvecm expected 1', ssh_password):
                    return True
            
            self.logger.error(f"[HA] Could not force quorum via SSH")
            self.logger.error(f"[HA] Manual fix: SSH to {target_node} and run: pvecm expected 1")
            self.logger.error(f"[HA] Tip: Configure SSH key in cluster settings for secure automatic SSH")
            return False
                
        except Exception as e:
            self.logger.error(f"[HA] Error forcing quorum: {e}")
            return False
    
    def _ha_check_restore_quorum(self):
        """Check if all nodes are online and restore quorum to normal
        
        NS: Jan 2026 - When a failed node comes back online in a 2-node cluster,
        we need to restore the expected votes from 1 back to 2.
        
        This runs: pvecm expected N (where N = number of nodes)
        """
        try:
            # Check if two_node_mode is enabled
            two_node_mode = self.ha_config.get('two_node_mode', False)
            force_quorum = self.ha_config.get('force_quorum_on_failure', False)
            
            if not (two_node_mode or force_quorum):
                # Not in special quorum mode, nothing to restore
                return
            
            # Count total and online nodes
            total_nodes = len(self.ha_node_status)
            online_nodes = sum(1 for n, s in self.ha_node_status.items() if s.get('status') == 'online')
            
            if total_nodes < 2:
                return
            
            # Only restore if ALL nodes are online
            if online_nodes < total_nodes:
                self.logger.info(f"[HA] {online_nodes}/{total_nodes} nodes online - waiting for all nodes before restoring quorum")
                return
            
            self.logger.info(f"[HA] ════════════════════════════════════════════════════════")
            self.logger.info(f"[HA] ALL NODES ONLINE - RESTORING QUORUM TO {total_nodes}")
            self.logger.info(f"[HA] ════════════════════════════════════════════════════════")
            
            # Pick any online node to run the command
            target_node = None
            for node_name, status in self.ha_node_status.items():
                if status.get('status') == 'online':
                    target_node = node_name
                    break
            
            if not target_node:
                self.logger.error("[HA] No online node found to restore quorum")
                return
            
            # Get target node IP
            node_ip = self._ha_get_node_ip(target_node)
            
            if not node_ip:
                self.logger.error(f"[HA] Cannot determine IP for {target_node}")
                return
            
            # Use cluster credentials
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            ssh_key = getattr(self.config, 'ssh_key', '')  # SSH key from cluster config
            
            restore_cmd = f'pvecm expected {total_nodes}'
            
            self.logger.info(f"[HA] Running '{restore_cmd}' on {target_node} ({node_ip})")
            
            # Method 1: Try SSH with configured key first (most secure)
            if ssh_key:
                if self._ssh_run_command_with_key(node_ip, ssh_user, restore_cmd, ssh_key):
                    self.logger.info(f"[HA] ✓ Quorum restored to {total_nodes} nodes")
                    broadcast_sse('ha_status', {
                        'event': 'quorum_restored',
                        'message': f'Quorum restored to {total_nodes} nodes',
                        'expected_votes': total_nodes,
                        'cluster_id': self.id
                    }, self.id)
                    return
            
            # Method 2: Try passwordless SSH
            if self._ssh_run_command(node_ip, ssh_user, restore_cmd):
                self.logger.info(f"[HA] ✓ Quorum restored to {total_nodes} nodes")
                broadcast_sse('ha_status', {
                    'event': 'quorum_restored',
                    'message': f'Quorum restored to {total_nodes} nodes',
                    'expected_votes': total_nodes,
                    'cluster_id': self.id
                }, self.id)
                return
            
            # Method 3: Try SSH with password
            if ssh_password:
                if self._ssh_run_command_with_password(node_ip, ssh_user, restore_cmd, ssh_password):
                    self.logger.info(f"[HA] ✓ Quorum restored to {total_nodes} nodes")
                    broadcast_sse('ha_status', {
                        'event': 'quorum_restored',
                        'message': f'Quorum restored to {total_nodes} nodes',
                        'expected_votes': total_nodes,
                        'cluster_id': self.id
                    }, self.id)
                    return
            
            self.logger.warning(f"[HA] Could not auto-restore quorum")
            self.logger.warning(f"[HA] Manual fix: SSH to any node and run: {restore_cmd}")
                
        except Exception as e:
            self.logger.error(f"[HA] Error restoring quorum: {e}")
    
    def _ha_get_node_ip(self, node_name: str) -> Optional[str]:
        """Get primary MANAGEMENT IP for a node.
        
        NS: Feb 2026 -- Uses _get_node_ip which does proper VLAN-aware discovery
        with reachability probing. This ensures we get the management IP (same VLAN
        as Pegaprox), NOT the Corosync or storage VLAN IP.
        
        For split-brain detection that needs ALL IPs, use _ha_get_all_node_ips().
        """
        # First: try the improved VLAN-aware discovery with probe
        mgmt_ip = self._get_node_ip(node_name)
        if mgmt_ip:
            return mgmt_ip
        
        # Fallback: get all IPs and pick first reachable
        ips = self._ha_get_all_node_ips(node_name)
        if ips:
            import socket
            for ip in ips:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    result = s.connect_ex((ip, 8006))
                    s.close()
                    if result == 0:
                        self.logger.info(f"[HA] {node_name} -> {ip} (fallback, reachable)")
                        return ip
                except:
                    continue
            # Last resort: return first IP (might not be reachable)
            self.logger.warning(f"[HA] {node_name}: no reachable IP found, using {ips[0]}")
            return ips[0]
        return None
    
    def _ha_get_all_node_ips(self, node_name: str) -> List[str]:
        """Get ALL IP addresses for a node (all networks!).
        
        This is CRITICAL for split-brain prevention in multi-network setups.
        If ANY network can reach the node, it's still alive!
        
        Management IPs are listed FIRST (most likely to be reachable from Pegaprox).
        """
        ips = []
        mgmt_ips = []  # Management IPs go first
        other_ips = []  # Corosync/storage IPs go after
        
        # Check manual override first
        node_ips = self.ha_config.get('node_ips', {})
        if node_name in node_ips:
            manual_ip = node_ips[node_name]
            if isinstance(manual_ip, list):
                mgmt_ips.extend(manual_ip)
            else:
                mgmt_ips.append(manual_ip)
        
        # Get management IP via _get_node_ip (VLAN-aware)
        try:
            best_ip = self._get_node_ip(node_name)
            if best_ip and best_ip not in mgmt_ips:
                mgmt_ips.insert(0, best_ip)
        except:
            pass
        
        # Try to get from cluster status (Corosync ring addresses)
        # NOTE: These are often on a DIFFERENT VLAN (Corosync network), so put in other_ips
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/cluster/status"
            resp = self._create_session().get(url, timeout=10)
            if resp.status_code == 200:
                for item in resp.json().get('data', []):
                    if item.get('type') == 'node' and item.get('name', '').lower() == node_name.lower():
                        coro_ip = item.get('ip')
                        if coro_ip and coro_ip not in mgmt_ips and coro_ip not in other_ips:
                            other_ips.append(coro_ip)
                            self.logger.debug(f"[HA] Found corosync IP {coro_ip} for {node_name} (may not be reachable from Pegaprox)")
        except Exception as e:
            self.logger.debug(f"[HA] Could not get cluster status for {node_name}: {e}")
        
        # Try to get all network interfaces from node config
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node_name.lower()}/network"
            resp = self._create_session().get(url, timeout=10)
            if resp.status_code == 200:
                for iface_data in resp.json().get('data', []):
                    addr = iface_data.get('address') or ''
                    if not addr:
                        cidr = iface_data.get('cidr', '')
                        if cidr:
                            addr = cidr.split('/')[0]
                    if addr and addr not in mgmt_ips and addr not in other_ips:
                        other_ips.append(addr)
        except Exception as e:
            self.logger.debug(f"[HA] Could not get network info for {node_name}: {e}")
        
        # Combine: management IPs first, then other IPs
        ips = []
        for ip in mgmt_ips:
            if ip and ip not in ips:
                ips.append(ip)
        for ip in other_ips:
            if ip and ip not in ips:
                ips.append(ip)
        
        # Try DNS resolution as fallback
        if not ips:
            try:
                import socket
                ip = socket.gethostbyname(node_name)
                if ip:
                    ips.append(ip)
            except:
                pass
            
            try:
                import socket
                for suffix in ['.local', '.lan', '.cluster']:
                    try:
                        ip = socket.gethostbyname(f"{node_name}{suffix}")
                        if ip and ip not in ips:
                            ips.append(ip)
                    except:
                        pass
            except:
                pass
        
        self.logger.debug(f"[HA] Node {node_name} IPs: {ips} (mgmt_first={mgmt_ips})")
        return ips
    
    def _ha_check_vm_locks_on_storage(self, node_name: str, vmids: List[int] = None) -> dict:
        """check if VMs still have active storage locks (catches iSCSI-up-but-server-down scenario)"""
        result = {'has_active_locks': False, 'locked_vms': [], 'lock_age': None}
        
        try:
            host = self.current_host or self.config.host
            
            # Get VMs on the node
            if vmids is None:
                vms_on_node = self._ha_get_vms_on_node(node_name)
                vmids = [vm.get('vmid') for vm in vms_on_node]
            
            for vmid in vmids:
                # Check if VM config has a lock
                url = f"https://{host}:8006/api2/json/nodes/{node_name}/qemu/{vmid}/config"
                try:
                    resp = self._create_session().get(url, timeout=5)
                    if resp.status_code == 200:
                        config = resp.json().get('data', {})
                        if config.get('lock'):
                            result['locked_vms'].append(vmid)
                            self.logger.warning(f"[HA] VM {vmid} has active lock: {config.get('lock')}")
                except:
                    pass
            
            result['has_active_locks'] = len(result['locked_vms']) > 0
            
            # Also check pmxcfs for recent activity from the node
            # The .members file in /etc/pve shows active nodes
            try:
                # This works because pmxcfs is a cluster filesystem
                # If we can read it, we can see all nodes' activity
                url = f"https://{host}:8006/api2/json/cluster/status"
                resp = self._create_session().get(url, timeout=5)
                if resp.status_code == 200:
                    for item in resp.json().get('data', []):
                        if item.get('type') == 'node' and item.get('name') == node_name:
                            # Check if node is still in quorum
                            if item.get('online') == 1:
                                self.logger.warning(f"[HA] ⚠️ Node {node_name} is still showing as ONLINE in cluster status!")
                                result['has_active_locks'] = True
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"[HA] Error checking VM locks: {e}")
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SCSI-3 PERSISTENT RESERVATIONS - TRUE STORAGE-LEVEL FENCING
    # NS Jan 2026
    #
    # This is the MOST RELIABLE method for dual-network setups!
    # The storage itself prevents split-brain by:
    # 1. Each node registers a "key" with the storage
    # 2. When fencing, we send a PREEMPT command to remove the dead node's key
    # 3. The storage then REFUSES all I/O from the dead node
    # 4. Even if the node is alive, it cannot corrupt data!
    #
    # Requires: sg3_utils package on PegaProx server and nodes
    # Works with: iSCSI, FC, SAS (any SCSI device)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _ha_scsi_fence_node(self, failed_node: str, vm_disks: List[str] = None) -> bool:
        """SCSI-3 persistent reservations fencing - blocks node from writing to disks"""
        if not self.ha_config.get('scsi_reservation_enabled', False):
            return False
        
        self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
        self.logger.info(f"[HA] SCSI-3 PERSISTENT RESERVATION FENCING for {failed_node}")
        self.logger.info(f"[HA] ═══════════════════════════════════════════════════════")
        
        try:
            # Get the surviving node
            surviving_node = None
            for node in self.ha_node_status:
                if node != failed_node and self.ha_node_status[node].get('status') == 'online':
                    surviving_node = node
                    break
            
            if not surviving_node:
                self.logger.error("[HA] No surviving node found for SCSI fencing")
                return False
            
            # Get SSH credentials
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            
            surviving_ip = self._ha_get_node_ip(surviving_node)
            if not surviving_ip:
                return False
            
            # Get the failed node's SCSI registration key
            # Convention: key is based on node name hash or configured
            failed_key = self.ha_config.get('scsi_keys', {}).get(failed_node)
            if not failed_key:
                # Generate key from node name (first 8 chars hex)
                failed_key = format(hash(failed_node) & 0xFFFFFFFFFFFFFFFF, '016x')[:16]
            
            self.logger.info(f"[HA] Failed node SCSI key: {failed_key}")
            
            # Get disks to fence
            if not vm_disks:
                vm_disks = self._ha_get_shared_disks_for_node(failed_node)
            
            if not vm_disks:
                self.logger.warning("[HA] No shared disks found to fence")
                return False
            
            fenced_disks = []
            
            for disk in vm_disks:
                self.logger.info(f"[HA] Fencing disk: {disk}")
                
                # Command to preempt the failed node's registration
                # sg_persist --out --preempt --param-sark=<failed_key> --prout-type=5 <device>
                fence_cmd = f"sg_persist --out --preempt --param-sark={failed_key} --prout-type=5 {disk} 2>&1"
                
                # Run on surviving node
                success = self._ssh_run_command_with_password(surviving_ip, ssh_user, fence_cmd, ssh_password)
                
                if success:
                    fenced_disks.append(disk)
                    self.logger.info(f"[HA] ✓ Disk {disk} fenced successfully")
                else:
                    self.logger.error(f"[HA] ✗ Failed to fence disk {disk}")
            
            if fenced_disks:
                self.logger.info(f"[HA] ✓ SCSI fencing complete: {len(fenced_disks)} disks fenced")
                return True
            else:
                self.logger.error("[HA] ✗ SCSI fencing failed - no disks could be fenced")
                return False
                
        except Exception as e:
            self.logger.error(f"[HA] SCSI fencing error: {e}")
            return False
    
    def _ha_get_shared_disks_for_node(self, node_name: str) -> List[str]:
        """Get list of shared storage disks used by VMs on a node"""
        disks = []
        
        try:
            # Get VMs on the node
            vms = self._ha_get_vms_on_node(node_name)
            
            for vm in vms:
                vmid = vm.get('vmid')
                
                # Get VM config to find disk paths
                host = self.current_host or self.config.host
                url = f"https://{host}:8006/api2/json/nodes/{node_name}/qemu/{vmid}/config"
                
                resp = self._create_session().get(url, timeout=5)
                if resp.status_code == 200:
                    config = resp.json().get('data', {})
                    
                    # Look for disk entries (scsi0, virtio0, etc.)
                    for key, value in config.items():
                        if any(key.startswith(prefix) for prefix in ['scsi', 'virtio', 'ide', 'sata']):
                            if isinstance(value, str):
                                # Parse disk path from "storage:vm-xxx-disk-0" format
                                # For iSCSI, this would be the actual device path
                                if '/' in value:
                                    disk_path = value.split(',')[0]
                                    if disk_path not in disks:
                                        disks.append(disk_path)
        except Exception as e:
            self.logger.error(f"[HA] Error getting shared disks: {e}")
        
        return disks
    
    def _ssh_run_command(self, host: str, user: str, command: str, key_file: str = None) -> bool:
        """Run SSH command on remote host - HA PRIORITY (no rate limiting)
        
        NS: Jan 2026 - HA operations bypass the semaphore because:
        1. They are critical (fencing must happen immediately)
        2. They are short (< 5 seconds typically)
        3. They are rare (only during actual failures)
        """
        _ssh_track_connection('ha', +1)
        
        try:
            ct = self.ha_config.get('ssh_connect_timeout', 10)
            ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', f'ConnectTimeout={ct}', '-o', 'BatchMode=yes']
            if key_file:
                ssh_cmd.extend(['-i', key_file])
            ssh_cmd.append(f'{user}@{host}')
            ssh_cmd.append(command)
            
            self.logger.info(f"[HA] Running: ssh {user}@{host} '{command}'")
            
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info(f"[HA] ✓ Command successful: {result.stdout.strip()}")
                return True
            else:
                self.logger.error(f"[HA] ✗ Command failed: {result.stderr.strip()}")
                return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"[HA] SSH command timed out")
            return False
        except FileNotFoundError:
            self.logger.error(f"[HA] SSH not found")
            return False
        finally:
            _ssh_track_connection('ha', -1)
    
    def _ssh_run_command_with_key(self, host: str, user: str, command: str, key_content: str) -> bool:
        """Run SSH command using a private key from cluster config
        
        MK: Security fix - writes key to temp file with strict permissions,
        uses it for SSH, then immediately deletes it.
        """
        import tempfile
        
        if not key_content or not key_content.strip():
            return False
        
        key_fd = None
        key_path = None
        
        try:
            # Write key to temp file with secure permissions (0600)
            key_fd, key_path = tempfile.mkstemp(prefix='pegaprox_ssh_', suffix='.key')
            os.chmod(key_path, 0o600)
            
            with os.fdopen(key_fd, 'w') as f:
                # Ensure key has proper newlines
                key_data = key_content.strip()
                if not key_data.endswith('\n'):
                    key_data += '\n'
                f.write(key_data)
            key_fd = None  # fd is now closed
            
            self.logger.info(f"[HA] Trying SSH with configured key...")
            
            # Run SSH with the key file
            result = self._ssh_run_command(host, user, command, key_file=key_path)
            
            return result
            
        except Exception as e:
            self.logger.error(f"[HA] SSH with key failed: {e}")
            return False
        finally:
            # Always clean up the temp key file
            if key_fd is not None:
                try:
                    os.close(key_fd)
                except:
                    pass
            if key_path and os.path.exists(key_path):
                try:
                    os.remove(key_path)
                except:
                    pass
    
    def _ssh_run_command_with_password(self, host: str, user: str, command: str, password: str) -> bool:
        """Run SSH command with password using sshpass - HA PRIORITY (no rate limiting)
        
        MK: Security fix - use SSHPASS environment variable instead of
        command line argument. Command line args are visible in 'ps aux'!
        
        NS: Jan 2026 - HA operations bypass semaphore for immediate execution
        """
        _ssh_track_connection('ha', +1)
        
        try:
            # Check if sshpass is available
            which_result = subprocess.run(['which', 'sshpass'], capture_output=True)
            if which_result.returncode != 0:
                self.logger.warning(f"[HA] sshpass not installed, trying without password...")
                _ssh_track_connection('ha', -1)  # Will be tracked by _ssh_run_command
                return self._ssh_run_command(host, user, command)
            
            ct = self.ha_config.get('ssh_connect_timeout', 10)
            ssh_cmd = [
                'sshpass', '-e',
                'ssh', '-o', 'StrictHostKeyChecking=no', '-o', f'ConnectTimeout={ct}',
                f'{user}@{host}',
                command
            ]
            
            env = os.environ.copy()
            env['SSHPASS'] = password
            
            self.logger.info(f"[HA] Running: sshpass ssh {user}@{host} '{command}'")
            
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30, env=env)
            
            if result.returncode == 0:
                self.logger.info(f"[HA] ✓ Command successful: {result.stdout.strip()}")
                return True
            else:
                self.logger.error(f"[HA] ✗ Command failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            self.logger.error(f"[HA] SSH with password failed: {e}")
            return False
        finally:
            _ssh_track_connection('ha', -1)
    
    def _ha_clear_vm_lock(self, vmid: int, vm_type: str, target_node: str, original_node: str) -> bool:
        """Clear VM/CT lock via Proxmox API. Returns True on success, False on failure."""
        host = self.current_host or self.config.host

        try:
            if vm_type == 'qemu':
                config_url = f"https://{host}:8006/api2/json/nodes/{target_node}/qemu/{vmid}/config"
            else:
                config_url = f"https://{host}:8006/api2/json/nodes/{target_node}/lxc/{vmid}/config"

            config_response = self._create_session().get(config_url, timeout=10)
            if config_response.status_code == 200:
                config = config_response.json().get('data', {})
                if 'lock' in config:
                    self.logger.info(f"[HA] {vm_type}/{vmid} has lock '{config['lock']}', clearing...")
                    unlock_response = self._create_session().put(
                        config_url,
                        data={'delete': 'lock'},
                        timeout=15
                    )
                    if unlock_response.status_code == 200:
                        self.logger.info(f"[HA] ✓ Cleared lock on {vm_type}/{vmid}")
                        return True
                    else:
                        self.logger.warning(f"[HA] Could not clear lock via API: {unlock_response.text}")
                        return False
                else:
                    return True  # No lock present = success
            else:
                self.logger.warning(f"[HA] Could not read config for {vm_type}/{vmid}: HTTP {config_response.status_code}")
                return False

        except Exception as e:
            self.logger.warning(f"[HA] Error clearing VM lock: {e}")
            return False
    
    def _ha_move_vm_config(self, vmid: int, vm_type: str, source_node: str, target_node: str) -> bool:
        """Move VM config file from source node to target node
        
        In Proxmox, VM configs are stored per-node at:
        - QEMU: /etc/pve/nodes/<node>/qemu-server/<vmid>.conf
        - LXC:  /etc/pve/nodes/<node>/lxc/<vmid>.conf
        
        For HA failover, we need to move the config to the new node.
        This is done via SSH since there's no API for this.
        """
        try:
            # Determine config paths
            if vm_type == 'qemu':
                source_path = f"/etc/pve/nodes/{source_node}/qemu-server/{vmid}.conf"
                target_path = f"/etc/pve/nodes/{target_node}/qemu-server/{vmid}.conf"
            else:
                source_path = f"/etc/pve/nodes/{source_node}/lxc/{vmid}.conf"
                target_path = f"/etc/pve/nodes/{target_node}/lxc/{vmid}.conf"
            
            self.logger.info(f"[HA] Moving VM {vmid} config: {source_path} -> {target_path}")
            
            # Get target node IP
            target_ip = self._ha_get_node_ip(target_node)
            if not target_ip:
                target_ip = self.current_host or self.config.host
            
            # Use cluster credentials for SSH
            api_user = self.config.user
            ssh_user = (api_user or 'root').split('@')[0]  # PR #62 (ry-ops): null-safe
            ssh_password = self.config.pass_
            
            # Build the move command - use mv to atomically move the config
            # The /etc/pve filesystem (pmxcfs) is cluster-aware
            move_cmd = f"mv {source_path} {target_path}"
            
            # Try passwordless SSH first
            if self._ssh_run_command(target_ip, ssh_user, move_cmd):
                return True
            
            # Try with password
            if ssh_password and self._ssh_run_command_with_password(target_ip, ssh_user, move_cmd, ssh_password):
                return True
            
            # Alternative: Try to copy instead of move (in case mv fails due to permissions)
            copy_cmd = f"cp {source_path} {target_path} && rm {source_path}"
            
            if self._ssh_run_command(target_ip, ssh_user, copy_cmd):
                return True
            
            if ssh_password and self._ssh_run_command_with_password(target_ip, ssh_user, copy_cmd, ssh_password):
                return True
            
            self.logger.error(f"[HA] ✗ Could not move VM config - SSH access required")
            self.logger.error(f"[HA] Manual fix: mv {source_path} {target_path}")
            return False
            
        except Exception as e:
            self.logger.error(f"[HA] Error moving VM config: {e}")
            return False
    
    def get_ha_status(self) -> Dict:
        
        
        # First, try to get node count from cluster if ha_node_status is empty
        # Do this OUTSIDE the lock to avoid deadlocks
        cluster_online = 0
        cluster_total = 0
        
        try:
            if self.is_connected:
                host = self.current_host or self.config.host
                url = f"https://{host}:8006/api2/json/nodes"
                session = self._create_session()
                response = session.get(url, timeout=5)
                if response.status_code == 200:
                    cluster_nodes = response.json().get('data', [])
                    cluster_total = len(cluster_nodes)
                    cluster_online = sum(1 for n in cluster_nodes if n.get('status') == 'online')
        except Exception as e:
            self.logger.debug(f"[HA] Could not fetch nodes for status: {e}")
        
        with self.ha_lock:
            # Count online/offline nodes from ha_node_status if available
            online_nodes = sum(1 for d in self.ha_node_status.values() if d.get('status') == 'online')
            total_nodes = len(self.ha_node_status)
            
            # If no nodes tracked yet, use cluster data
            if total_nodes == 0 and cluster_total > 0:
                total_nodes = cluster_total
                online_nodes = cluster_online
            
            # Determine status
            if total_nodes == 0:
                health_status = 'unknown'
            elif online_nodes == total_nodes:
                health_status = 'healthy'
            elif online_nodes > 0:
                health_status = 'degraded'
            else:
                health_status = 'critical'
            
            return {
                'enabled': self.ha_enabled,
                'check_interval': self.ha_check_interval,
                'failure_threshold': self.ha_failure_threshold,
                'nodes': {
                    name: {
                        'status': data['status'],
                        'last_seen': data['last_seen'].isoformat() if data.get('last_seen') else None,
                        'consecutive_failures': data.get('consecutive_failures', 0)
                    }
                    for name, data in self.ha_node_status.items()
                },
                'recovery_in_progress': list(self.ha_recovery_in_progress.keys()),
                'fallback_hosts': self.config.fallback_hosts,
                
                # Split-brain prevention status
                'split_brain_prevention': {
                    'quorum_enabled': self.ha_config.get('quorum_enabled', True),
                    'have_quorum': self.ha_have_quorum,
                    'last_quorum_check': self.ha_last_quorum_check.isoformat() if self.ha_last_quorum_check else None,
                    'self_fence_enabled': self.ha_config.get('self_fence_enabled', True),
                    'watchdog_enabled': self.ha_config.get('watchdog_enabled', False),
                    'recovery_delay': self.ha_config.get('recovery_delay', 30),
                    'quorum_hosts': self.ha_config.get('quorum_hosts', []),
                    'quorum_gateway': self.ha_config.get('quorum_gateway', ''),
                    'quorum_required_votes': self.ha_config.get('quorum_required_votes', 2),
                    'verify_network': self.ha_config.get('verify_network_before_recovery', True),
                    # 2-Node Mode
                    'two_node_mode': self.ha_config.get('two_node_mode', False),
                    # Storage-based Split-Brain Protection - NS Jan 2026
                    'storage_heartbeat_enabled': self.ha_config.get('storage_heartbeat_enabled', False),
                    'storage_heartbeat_path': self.ha_config.get('storage_heartbeat_path', ''),
                    'storage_heartbeat_timeout': self.ha_config.get('storage_heartbeat_timeout', 30),
                    'poison_pill_enabled': self.ha_config.get('poison_pill_enabled', True),
                    'strict_fencing': self.ha_config.get('strict_fencing', False),
                    'last_heartbeat_write': self.ha_last_heartbeat_write.isoformat() if self.ha_last_heartbeat_write else None,
                },
                
                # Cluster health summary
                'cluster_health': {
                    'online_nodes': online_nodes,
                    'total_nodes': total_nodes,
                    'is_2_node_cluster': total_nodes == 2,
                    'status': health_status
                },
                
                # Auto-discovered shared storages - NS Jan 2026
                'discovered_storages': getattr(self, '_cached_shared_storages', []),
                'block_storages': getattr(self, '_cached_block_storages', []),
                'auto_protection_active': bool(self.ha_config.get('storage_heartbeat_path')),
                
                # Self-Fence Protection - NS Jan 2026
                'self_fence_installed': self.ha_config.get('self_fence_installed', False),
                'self_fence_nodes': self.ha_config.get('self_fence_nodes', []),
            }
    
    def get_tasks(self, limit: int = 50) -> List[Dict]:
        """get recent cluster tasks, newest first - MK"""
        # Fail early if we're not connected to avoid hanging
        if not self.is_connected or not self.session:
            return []
        
        tasks = []
        try:
            host = self.current_host or self.config.host
            
            # Get cluster-wide tasks
            url = f"https://{host}:8006/api2/json/cluster/tasks"
            response = self._create_session().get(url, timeout=10)
            
            if response.status_code == 200:
                cluster_tasks = response.json().get('data', [])
                for task in cluster_tasks[:limit]:
                    # Parse the task and extract useful info
                    task_info = {
                        'upid': task.get('upid', ''),
                        'node': task.get('node', ''),
                        'type': task.get('type', ''),
                        'status': task.get('status', 'running'),
                        'starttime': task.get('starttime'),
                        'endtime': task.get('endtime'),
                        'user': task.get('user', ''),  # Proxmox user (e.g. root@pam)
                        'id': task.get('id', ''),
                    }
                    
                    # NS: Add PegaProx user who initiated this task (if known)
                    from pegaprox.api.helpers import get_task_user
                    pegaprox_user = get_task_user(task_info['upid'])
                    if pegaprox_user:
                        task_info['pegaprox_user'] = pegaprox_user
                    
                    # Parse VMID from ID if present
                    if task_info['id']:
                        try:
                            task_info['vmid'] = int(task_info['id'])
                        except (ValueError, TypeError):
                            task_info['vmid'] = task_info['id']
                    
                    # Get exit status for completed tasks
                    if getattr(task, 'status', None) and task['status'] != 'running':
                        task_info['exitstatus'] = task.get('exitstatus', '')
                        # Mark as failed if exit status indicates error
                        if task_info['exitstatus'] and 'error' in task_info['exitstatus'].lower():
                            task_info['status'] = 'failed'
                            task_info['error'] = task_info['exitstatus']
                        elif task_info['exitstatus'] and task_info['exitstatus'] != 'OK':
                            task_info['status'] = 'failed'
                            task_info['error'] = task_info['exitstatus']
                    
                    tasks.append(task_info)
            
            # Sort by starttime descending (newest first)
            tasks.sort(key=lambda x: x.get('starttime') or 0, reverse=True)
            
            return tasks
            
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            # MK: don't immediately mark disconnected - transient errors happen
            return []
        except Exception as e:
            self.logger.error(f"Error getting tasks: {e}")
            return []
    
    def get_datacenter_options(self) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/cluster/options"
            response = self._create_session().get(url, timeout=15)
            
            if response.status_code == 200:
                options = response.json().get('data', {})
                return {
                    'success': True,
                    'options': {
                        'task_log_max_days': options.get('max-workers', 4),  # Default 4
                        'console': options.get('console', 'default'),
                        'keyboard': options.get('keyboard', ''),
                        'language': options.get('language', ''),
                        'email_from': options.get('email_from', ''),
                        'migration_type': options.get('migration', {}).get('type', 'secure'),
                        'migration_network': options.get('migration', {}).get('network', ''),
                        'ha_shutdown_policy': options.get('ha', {}).get('shutdown_policy', 'conditional'),
                        # Raw options for reference
                        'raw': options
                    }
                }
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            self.logger.error(f"Error getting datacenter options: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_task(self, node: str, upid: str) -> bool:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return False
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/tasks/{upid}"
            response = self._api_delete(url)
            
            if response.status_code == 200:
                self.logger.info(f"Task {upid} cancelled on {node}")
                return True
            else:
                self.logger.error(f"Failed to cancel task {upid}: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Error cancelling task: {e}")
            return False
    
    def get_task_log(self, node: str, upid: str, limit: int = 1000) -> str:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return "Error: Not connected to Proxmox"
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/tasks/{upid}/log"
            params = {'limit': limit}
            response = self._create_session().get(url, params=params)
            
            if response.status_code == 200:
                data = response.json().get('data', [])
                # Combine log lines
                log_lines = []
                for entry in sorted(data, key=lambda x: x.get('n', 0)):
                    line = entry.get('t', '')
                    log_lines.append(line)
                return '\n'.join(log_lines)
            else:
                return f"Error: Could not fetch log (Status {response.status_code})"
        except Exception as e:
            self.logger.error(f"Error getting task log: {e}")
            return f"Error: {str(e)}"
    
    # =====================================================
    # PROXMOX NATIVE HA INTEGRATION
    # =====================================================
    
    def get_proxmox_ha_resources(self) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/cluster/ha/resources"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting Proxmox HA resources: {e}")
            return []
    
    def get_proxmox_ha_groups(self) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/cluster/ha/groups"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting Proxmox HA groups: {e}")
            return []
    
    def add_vm_to_proxmox_ha(self, vmid: int, vm_type: str = 'vm', group: str = None, 
                             max_restart: int = 1, max_relocate: int = 1, state: str = 'started',
                             comment: str = None) -> Dict:
        """add VM/CT to Proxmox native HA with restart/relocate limits"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Not connected'}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/cluster/ha/resources"
            
            # sid format: vm:100 or ct:100
            sid = f"{vm_type}:{vmid}"
            
            data = {
                'sid': sid,
                'max_restart': max_restart,
                'max_relocate': max_relocate,
                'state': state or 'started'
            }
            
            if group:
                data['group'] = group
            if comment:
                data['comment'] = comment
            
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[HA] Added {sid} to Proxmox HA")
                return {'success': True, 'message': f'{sid} added to HA'}
            else:
                error = response.text
                self.logger.error(f"[HA] Failed to add {sid} to HA: {error}")
                return {'success': False, 'error': error}
                
        except Exception as e:
            self.logger.error(f"Error adding to Proxmox HA: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_vm_from_proxmox_ha(self, vmid: int, vm_type: str = 'vm') -> Dict:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Not connected'}
        
        try:
            host = self.current_host or self.config.host
            sid = f"{vm_type}:{vmid}"
            url = f"https://{host}:8006/api2/json/cluster/ha/resources/{sid}"
            
            response = self._api_delete(url)
            
            if response.status_code == 200:
                self.logger.info(f"[HA] Removed {sid} from Proxmox HA")
                return {'success': True, 'message': f'{sid} removed from HA'}
            else:
                error = response.text
                self.logger.error(f"[HA] Failed to remove {sid} from HA: {error}")
                return {'success': False, 'error': error}
                
        except Exception as e:
            self.logger.error(f"Error removing from Proxmox HA: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_node_ip(self, node_name: str) -> Optional[str]:
        """Get the best REACHABLE management IP address for a node.
        
        NS: Feb 2026 - Fixed for VLAN setups (vmbr0 / vmbr0.10 / vmbr0.510):
        
        Works for ANY management interface:
          - vmbr0         (flat, no VLAN)
          - vmbr0.10      (VLAN 10)
          - vmbr0.510     (VLAN 510)
          - vmbr1.100     (second bridge, VLAN 100)
          - bond0 / eno1  (direct interface, no bridge)
        
        Strategy:
        1. Query the CURRENT/PRIMARY node to find which interface has the mgmt IP
        2. On the TARGET node, find the IP on the SAME interface name (vmbr0.10 -> vmbr0.10)
        3. Fall back to same CIDR network
        4. Verify reachability with TCP probe (port 8006)
        5. NEVER blindly use Corosync/storage IPs
        """
        try:
            import ipaddress, socket
            
            if not self.is_connected:
                if not self.connect_to_proxmox():
                    return None
            
            host = self.current_host or self.config.host
            primary_ip = self.config.host

            # If target is the local/primary node, return its IP directly
            # Otherwise the logic below skips it (ip == primary_ip filter)
            try:
                cs_url = f"https://{host}:8006/api2/json/cluster/status"
                cs_resp = self._api_get(cs_url)
                if cs_resp.status_code == 200:
                    for item in cs_resp.json().get('data', []):
                        if item.get('type') == 'node' and item.get('name') == node_name and item.get('local', 0) == 1:
                            self.logger.info(f"[NodeIP] {node_name} is the local node, using {primary_ip}")
                            return primary_ip
            except Exception:
                pass

            def _parse_cidr(addr_str, cidr_str=None, netmask_str=None):
                try:
                    if cidr_str and '/' in cidr_str:
                        return ipaddress.ip_interface(cidr_str)  # Auto IPv4/IPv6
                    if netmask_str:
                        return ipaddress.ip_interface(f"{addr_str}/{netmask_str}")
                    # Default prefix: /24 for IPv4, /64 for IPv6
                    prefix = '/64' if ':' in addr_str else '/24'
                    return ipaddress.ip_interface(f"{addr_str}{prefix}")
                except Exception:
                    return None
            
            def _quick_probe(ip, port=8006, timeout=2):
                """Quick TCP probe to check if IP:port is reachable (IPv4+IPv6)."""
                try:
                    # Issue #71: Detect address family for IPv6 support
                    af = socket.AF_INET6 if ':' in ip else socket.AF_INET
                    s = socket.socket(af, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    s.close()
                    return result == 0
                except Exception:
                    return False
            
            try:
                primary_parsed = ipaddress.ip_address(primary_ip)  # IPv4 or IPv6
            except Exception:
                primary_parsed = None
            
            # ================================================================
            # STEP 0 (Issue #71): Quick path -- get IP from cluster/status
            # The Proxmox cluster/status API returns each node's IP directly.
            # This often works even when the complex interface matching fails
            # (e.g., different VLANs, IPv6-only, or node offline via API).
            # ================================================================
            try:
                cs_url = f"https://{host}:8006/api2/json/cluster/status"
                cs_resp = self._api_get(cs_url)
                if cs_resp.status_code == 200:
                    for item in cs_resp.json().get('data', []):
                        if item.get('type') == 'node' and item.get('name') == node_name:
                            node_direct_ip = item.get('ip', '')
                            if node_direct_ip and node_direct_ip != primary_ip:
                                if _quick_probe(node_direct_ip):
                                    self.logger.info(f"[NodeIP] {node_name} -> {node_direct_ip} (from cluster/status, reachable)")
                                    return node_direct_ip
                                else:
                                    self.logger.debug(f"[NodeIP] {node_name}: cluster/status IP {node_direct_ip} not reachable on 8006, continuing...")
                            break
            except Exception as e:
                self.logger.debug(f"[NodeIP] cluster/status quick path failed: {e}")
            
            # ================================================================
            # STEP 1: Find which interface the PRIMARY node uses for management
            # Query the PRIMARY node, NOT the target -- this was the old bug
            # ================================================================
            primary_iface = None        # e.g., 'vmbr0.10' or 'vmbr0'
            primary_network = None      # ipaddress.IPv4Network
            primary_vlan_id = None      # e.g., '10', '510', or None
            
            # Cache per-cluster to avoid repeated API calls
            if not hasattr(self, '_cached_mgmt_iface'):
                self._cached_mgmt_iface = None
                self._cached_mgmt_network = None
                self._cached_mgmt_vlan = None
            
            if self._cached_mgmt_iface:
                primary_iface = self._cached_mgmt_iface
                primary_network = self._cached_mgmt_network
                primary_vlan_id = self._cached_mgmt_vlan
            else:
                try:
                    # Find current node name
                    status_url = f"https://{host}:8006/api2/json/cluster/status"
                    status_resp = self._api_get(status_url)
                    current_node_name = None
                    if status_resp.status_code == 200:
                        for item in status_resp.json().get('data', []):
                            if item.get('type') == 'node' and item.get('local', 0) == 1:
                                current_node_name = item.get('name')
                                break
                    
                    if not current_node_name:
                        nodes_url = f"https://{host}:8006/api2/json/nodes"
                        nodes_resp = self._api_get(nodes_url)
                        if nodes_resp.status_code == 200:
                            for n in nodes_resp.json().get('data', []):
                                if n.get('status') == 'online':
                                    current_node_name = n.get('node')
                                    break
                    
                    if current_node_name:
                        net_url = f"https://{host}:8006/api2/json/nodes/{current_node_name}/network"
                        net_resp = self._api_get(net_url)
                        if net_resp.status_code == 200:
                            for net in net_resp.json().get('data', []):
                                addr = net.get('address') or ''
                                if not addr:
                                    continue
                                try:
                                    if ipaddress.ip_address(addr) == primary_parsed:
                                        primary_iface = net.get('iface', '')
                                        ci = net.get('cidr', '')
                                        nm = net.get('netmask', '')
                                        pi = _parse_cidr(addr, ci, nm)
                                        if pi:
                                            primary_network = pi.network
                                        if '.' in primary_iface:
                                            primary_vlan_id = primary_iface.rsplit('.', 1)[-1]
                                        self._cached_mgmt_iface = primary_iface
                                        self._cached_mgmt_network = primary_network
                                        self._cached_mgmt_vlan = primary_vlan_id
                                        self.logger.info(f"[NodeIP] Mgmt interface: {primary_iface} ({primary_ip}/{pi.network.prefixlen if pi else '?'}) VLAN={primary_vlan_id or 'none'}")
                                        break
                                except Exception:
                                    continue
                except Exception as e:
                    self.logger.debug(f"[NodeIP] Could not detect primary interface: {e}")
            
            # ================================================================
            # STEP 2: Get ALL network interfaces from the TARGET node
            # ================================================================
            url = f"https://{host}:8006/api2/json/nodes/{node_name}/network"
            response = self._api_get(url)
            
            candidates = []
            
            if response.status_code == 200:
                networks = response.json().get('data', [])
                
                for net in networks:
                    iface = net.get('iface', '')
                    net_type = net.get('type', '')
                    
                    if iface.startswith('lo') or iface.startswith('tun') or iface.startswith('tap') or iface.startswith('veth'):
                        continue
                    
                    # Issue #71: Collect both IPv4 and IPv6 addresses from each interface
                    addr_candidates = []
                    # IPv4
                    addr4 = net.get('address') or net.get('address4') or ''
                    if addr4 and not addr4.startswith('127.'):
                        addr_candidates.append((addr4, net.get('cidr', ''), net.get('netmask', '')))
                    # IPv6 (Proxmox reports as address6/cidr6)
                    addr6 = net.get('address6') or ''
                    if addr6 and addr6 != '::1' and not addr6.startswith('fe80:'):  # Skip link-local
                        addr_candidates.append((addr6, net.get('cidr6', ''), ''))
                    
                    for addr, cidr, netmask in addr_candidates:
                        parsed = _parse_cidr(addr, cidr, netmask)
                        if not parsed:
                            continue
                        
                        is_bridge = iface.startswith('vmbr') or net_type in ('bridge', 'OVSBridge')
                        is_vlan = '.' in iface or net_type in ('vlan', 'OVSIntPort')
                        
                        this_vlan_id = None
                        if '.' in iface:
                            this_vlan_id = iface.rsplit('.', 1)[-1]
                        
                        # SCORING:
                        # 100: EXACT same interface name (vmbr0.10 <-> vmbr0.10)
                        #  95: Same VLAN ID, different bridge (vmbr0.10 <-> vmbr1.10)
                        #  85: Same IP network + bridge/vlan
                        #  80: Same IP network, any interface
                        #  70: Non-VLAN bridge when primary is also non-VLAN
                        #  40: Non-VLAN bridge when primary IS on a VLAN
                        #  20: VLAN on different network (Corosync/NFS)
                        #  30: Any other interface
                        
                        score = 30
                        reason = f"iface={iface}"
                        
                        if primary_iface and iface == primary_iface:
                            score = 100
                            reason = f"exact_match {iface}"
                        elif primary_vlan_id and this_vlan_id == primary_vlan_id:
                            score = 95
                            reason = f"same_vlan .{this_vlan_id} via {iface}"
                        elif primary_parsed and parsed:
                            try:
                                same_net = primary_parsed in parsed.network
                            except Exception:
                                same_net = False
                            if same_net:
                                score = 85 if (is_bridge or is_vlan) else 80
                                reason = f"same_network via {iface}"
                        elif is_bridge and not is_vlan:
                            if primary_iface and '.' not in primary_iface:
                                score = 70
                                reason = f"bridge_no_vlan {iface}"
                            else:
                                score = 40
                                reason = f"bridge_but_primary_is_vlan {iface}"
                        elif is_vlan:
                            score = 20
                            reason = f"vlan_no_match {iface}"
                        
                        candidates.append((score, addr, iface, reason))
                        self.logger.debug(f"[NodeIP] {node_name}: {addr} ({iface}) score={score} -- {reason}")
            
            candidates.sort(key=lambda x: x[0], reverse=True)
            
            # ================================================================
            # STEP 3: Try candidates with connectivity probe
            # ================================================================
            for score, ip, iface, reason in candidates:
                if score < 20 or ip == primary_ip:
                    continue
                if _quick_probe(ip):
                    self.logger.info(f"[NodeIP] {node_name} -> {ip} (score={score}, {reason}) reachable")
                    return ip
                else:
                    self.logger.debug(f"[NodeIP] {node_name}: {ip} score={score} NOT reachable")
            
            # ================================================================
            # STEP 4: Corosync -- ONLY if in management network
            # ================================================================
            try:
                coro_url = f"https://{host}:8006/api2/json/cluster/config/nodes"
                coro_resp = self._api_get(coro_url)
                if coro_resp.status_code == 200:
                    for node in coro_resp.json().get('data', []):
                        if node.get('name') == node_name:
                            for key, value in node.items():
                                if key.startswith('link') and value:
                                    link_ip = value.split(',')[0].strip()
                                    if not link_ip or link_ip.startswith('127.') or link_ip == '::1':
                                        continue
                                    try:
                                        la = ipaddress.ip_address(link_ip)
                                        if primary_network and la in primary_network:
                                            if _quick_probe(link_ip):
                                                self.logger.info(f"[NodeIP] {node_name} -> {link_ip} (corosync {key}, mgmt net) reachable")
                                                return link_ip
                                        else:
                                            self.logger.debug(f"[NodeIP] SKIP corosync {link_ip} ({key}) -- not in mgmt network")
                                    except Exception:
                                        pass
            except Exception:
                pass
            
            # ================================================================
            # STEP 5: High-confidence without probe (firewall may block)
            # ================================================================
            for score, ip, iface, reason in candidates:
                if score >= 85 and ip != primary_ip:
                    self.logger.warning(f"[NodeIP] {node_name} -> {ip} (score={score}, {reason}) -- probe failed, high confidence")
                    return ip
            
            # ================================================================
            # STEP 6: DNS / hostname fallback
            # ================================================================
            try:
                # Use getaddrinfo instead of gethostbyname (supports both IPv4+IPv6)
                import socket
                addrs = socket.getaddrinfo(node_name, 8006, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for af, socktype, proto, canonname, sa in addrs:
                    ip = sa[0]
                    if ip and ip != primary_ip and not ip.startswith('127.') and ip != '::1':
                        if _quick_probe(ip):
                            self.logger.info(f"[NodeIP] Resolved {node_name} to {ip} (DNS, {'IPv6' if af == socket.AF_INET6 else 'IPv4'})")
                            return ip
                # If probe failed, return first result anyway
                for af, socktype, proto, canonname, sa in addrs:
                    ip = sa[0]
                    if ip and not ip.startswith('127.') and ip != '::1':
                        self.logger.info(f"[NodeIP] Resolved {node_name} to {ip} (DNS, no probe)")
                        return ip
            except (socket.gaierror, OSError):
                pass
            
            if node_name in self.config.host:
                return self.config.host
            
            self.logger.warning(f"[NodeIP] No reachable management IP for {node_name}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting node IP: {e}")
            return None


    def _ssh_connect(self, host: str, retries: int = 3, retry_delay: float = 2.0):
        """SSH connect with retry logic and connection rate limiting
        
        NS: Jan 2026 - Limits concurrent CONNECTION ATTEMPTS (not active sessions).
        The semaphore is released after successful connection, allowing new
        connections while this one is active. This prevents connection storms
        while not blocking long-running operations.
        
        HA operations use separate methods without any rate limiting.
        """
        paramiko = get_paramiko()
        if not paramiko:
            self.logger.error("paramiko not installed, cannot use SSH features")
            return None
        
        # Get connection parameters
        username = self.config.ssh_user if self.config.ssh_user else self.config.user.split('@')[0]
        ssh_port = getattr(self.config, 'ssh_port', 22) or 22
        ssh_key = getattr(self.config, 'ssh_key', '')
        
        for attempt in range(1, retries + 1):
            # Rate limit connection ATTEMPTS (not active connections)
            stats = get_ssh_connection_stats()
            self.logger.debug(f"SSH queue: {stats['active_normal']} connecting, {stats['active_ha']} HA active")
            
            acquired = _g._ssh_semaphore.acquire(timeout=120)
            if not acquired:
                self.logger.error(f"SSH to {host} queued too long (120s) - increase PEGAPROX_SSH_MAX_CONCURRENT")
                return None
            
            _ssh_track_connection('normal', +1)
            
            try:
                if attempt > 1:
                    self.logger.info(f"SSH retry {attempt}/{retries} to {host}...")
                else:
                    self.logger.info(f"Connecting to {host}:{ssh_port} as {username}...")
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': host,
                    'port': ssh_port,
                    'username': username,
                    'timeout': 30,
                    'banner_timeout': 30,
                    'allow_agent': False,
                    'look_for_keys': False
                }
                
                if ssh_key:
                    import io
                    key_file = io.StringIO(ssh_key)
                    pkey = None
                    for key_name, key_class in [
                        ('RSA', paramiko.RSAKey),
                        ('Ed25519', paramiko.Ed25519Key),
                        ('ECDSA', paramiko.ECDSAKey),
                        ('DSA', getattr(paramiko, 'DSSKey', None))
                    ]:
                        if key_class is None:
                            continue
                        try:
                            key_file.seek(0)
                            pkey = key_class.from_private_key(key_file)
                            break
                        except:
                            continue

                    if not pkey:
                        self.logger.error("Could not load SSH key - unsupported format")
                        return None
                    
                    connect_kwargs['pkey'] = pkey
                else:
                    connect_kwargs['password'] = self.config.pass_
                
                ssh.connect(**connect_kwargs)
                self.logger.info(f"SSH connected to {host}" + (f" (attempt {attempt})" if attempt > 1 else ""))
                
                # SUCCESS - release semaphore immediately, connection is established
                # This allows new connections while this session runs
                return ssh
                
            except paramiko.ssh_exception.AuthenticationException as e:
                self.logger.error(f"SSH auth failed for {username}@{host}: {e}")
                return None
                
            except (paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, TimeoutError) as e:
                if attempt < retries:
                    delay = retry_delay * (2 ** (attempt - 1))
                    self.logger.warning(f"SSH to {host} failed (attempt {attempt}), retry in {delay}s...")
                    time.sleep(delay)
                    continue
                self.logger.error(f"SSH to {host} failed after {retries} attempts: {e}")
                return None
                
            except Exception as e:
                if attempt < retries:
                    delay = retry_delay * (2 ** (attempt - 1))
                    self.logger.warning(f"SSH error (attempt {attempt}), retry in {delay}s: {e}")
                    time.sleep(delay)
                    continue
                self.logger.error(f"SSH to {host} failed: {e}")
                return None
                
            finally:
                # Always release semaphore after attempt (success or failure)
                _ssh_track_connection('normal', -1)
                _g._ssh_semaphore.release()
        
        return None
    
    def _ssh_execute(self, ssh, command: str, task: UpdateTask = None) -> tuple:
        
        try:
            self.logger.info(f"Executing: {command}")
            
            stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
            
            output_lines = []
            
            # Read output line by line
            for line in iter(stdout.readline, ''):
                line = line.strip()
                if line:
                    output_lines.append(line)
                    if task:
                        task.add_output(line)
                    self.logger.debug(f"SSH: {line}")
            
            exit_code = stdout.channel.recv_exit_status()
            
            # Also capture any stderr
            stderr_output = stderr.read().decode('utf-8').strip()
            if stderr_output and task:
                for line in stderr_output.split('\n'):
                    if line.strip():
                        task.add_output(f"[stderr] {line.strip()}")
            
            return exit_code, '\n'.join(output_lines), stderr_output
            
        except Exception as e:
            self.logger.error(f"SSH execute error: {e}")
            return -1, '', str(e)
    
    def _wait_for_node_online(self, node_name: str, timeout: int = 600) -> bool:
        
        self.logger.info(f"Waiting for {node_name} to come back online (timeout: {timeout}s)...")
        start_time = time.time()
        
        # First wait a bit for the node to actually go down
        # 30s seems to work, less and you get false positives
        time.sleep(30)
        
        while time.time() - start_time < timeout:
            try:
                # Try to get node status from Proxmox API
                # Force reconnect in case session expired
                self.session = None  # force new session
                if self.connect_to_proxmox():
                    node_status = self.get_node_status()
                    if node_name in node_status:
                        if node_status[node_name]['status'] == 'online':
                            self.logger.info(f"[OK] {node_name} is back online!")
                            return True
                
            except Exception as e:
                self.logger.debug(f"Waiting for {node_name}: {e}")
            
            time.sleep(10)
        
        self.logger.error(f"Timeout waiting for {node_name} to come online")
        return False
    
    def start_node_update(self, node_name: str, reboot: bool = True, force: bool = False) -> Optional[UpdateTask]:
        
        # check node is in maintenance mode (unless force)
        if not force:
            if node_name not in self.nodes_in_maintenance:
                self.logger.error(f"Cannot update {node_name}: not in maintenance mode")
                return None
            
            maintenance_task = self.nodes_in_maintenance[node_name]
            if maintenance_task.status not in ['completed', 'completed_with_errors']:
                self.logger.error(f"Cannot update {node_name}: evacuation not complete")
                return None
        else:
            self.logger.warning(f"Force-updating {node_name} without maintenance mode!")
        
        # check already updating
        with self.update_lock:
            if node_name in self.nodes_updating:
                return self.nodes_updating[node_name]
            
            task = UpdateTask(node_name, reboot)
            self.nodes_updating[node_name] = task
        
        self.logger.info(f"[SYNC] Starting update for node: {node_name} (reboot: {reboot}, force: {force})")
        
        # Start update in background - use gevent if available for paramiko compatibility
        if GEVENT_PATCHED:
            try:
                import gevent
                gevent.spawn(self._perform_node_update, node_name, task)
                self.logger.info(f"[SYNC] Update spawned with gevent greenlet")
            except Exception as e:
                self.logger.warning(f"Gevent spawn failed, falling back to thread: {e}")
                update_thread = threading.Thread(
                    target=self._perform_node_update,
                    args=(node_name, task)
                )
                update_thread.daemon = True
                update_thread.start()
        else:
            update_thread = threading.Thread(
                target=self._perform_node_update,
                args=(node_name, task)
            )
            update_thread.daemon = True
            update_thread.start()
        
        return task
    
    def _perform_node_update(self, node_name: str, task: UpdateTask):
        
        ssh = None
        
        try:
            task.status = 'updating'
            task.phase = 'connecting'
            task.add_output(f"Connecting to / Verbinde zu {node_name}...")
            
            # Get node IP
            node_ip = self._get_node_ip(node_name)
            if not node_ip:
                raise Exception(f"Could not determine IP for {node_name}")
            
            task.add_output(f"Node IP: {node_ip}")
            
            # Connect via SSH
            ssh = self._ssh_connect(node_ip)
            if not ssh:
                # Check why SSH failed - get username for hint
                if self.config.ssh_user:
                    username = self.config.ssh_user
                else:
                    username = self.config.user.split('@')[0]
                ssh_port = getattr(self.config, 'ssh_port', 22) or 22
                
                if self.config.ssh_key:
                    raise Exception(f"SSH connection failed to {username}@{node_ip}:{ssh_port} - Check SSH key configuration / SSH Verbindung fehlgeschlagen - Prüfe SSH Key Konfiguration")
                else:
                    raise Exception(f"SSH connection failed to {username}@{node_ip}:{ssh_port} - Check if password auth is enabled on the node or configure an SSH key / SSH Verbindung fehlgeschlagen - Prüfe ob Passwort-Auth auf dem Node aktiviert ist oder konfiguriere einen SSH Key")
            
            task.add_output("SSH connection established / SSH Verbindung hergestellt")
            
            # Check if we're root (common on Proxmox) - if so, no sudo needed
            stdin, stdout, stderr = ssh.exec_command('id -u')
            uid = stdout.read().decode().strip()
            sudo_prefix = '' if uid == '0' else 'sudo '
            
            if uid == '0':
                task.add_output("Running as root - no sudo needed")
            else:
                task.add_output(f"Running as uid {uid} - using sudo")
            
            # Phase 1: apt update
            task.phase = 'apt_update'
            task.add_output("Running apt update...")
            
            exit_code, output, stderr = self._ssh_execute(
                ssh, 
                f'{sudo_prefix}DEBIAN_FRONTEND=noninteractive apt-get update',
                task
            )
            
            if exit_code != 0:
                raise Exception(f"apt update failed / fehlgeschlagen: {stderr}")
            
            task.add_output("[OK] apt update successful / erfolgreich")
            
            # Phase 2: apt dist-upgrade
            task.phase = 'apt_upgrade'
            task.add_output("Running apt dist-upgrade...")
            
            exit_code, output, stderr = self._ssh_execute(
                ssh,
                f'{sudo_prefix}DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"',
                task
            )
            
            if exit_code != 0:
                raise Exception(f"apt dist-upgrade failed / fehlgeschlagen: {stderr}")
            
            # Count upgraded packages (rough estimate from output)
            if 'upgraded' in output.lower():
                for line in output.split('\n'):
                    if 'upgraded' in line.lower() and 'newly installed' in line.lower():
                        parts = line.split()
                        try:
                            task.packages_upgraded = int(parts[0])
                        except:
                            pass
            
            task.add_output(f"[OK] apt dist-upgrade successful / erfolgreich ({task.packages_upgraded} packages / Pakete)")
            
            # Phase 3: Cleanup
            task.add_output("Cleaning up / Aufräumen...")
            self._ssh_execute(ssh, f'{sudo_prefix}apt-get autoremove -y', task)
            self._ssh_execute(ssh, f'{sudo_prefix}apt-get autoclean', task)
            
            # Close SSH before reboot
            ssh.close()
            ssh = None
            
            # Phase 4: Reboot if requested
            if task.reboot:
                task.phase = 'reboot'
                task.status = 'rebooting'
                task.add_output("[SYNC] Initiating reboot / Starte Neustart...")
                
                # Reconnect for reboot command
                ssh = self._ssh_connect(node_ip)
                if ssh:
                    try:
                        # Check if root
                        stdin, stdout, stderr = ssh.exec_command('id -u')
                        uid = stdout.read().decode().strip()
                        is_root = (uid == '0')
                        
                        self.logger.info(f"Sending reboot command to {node_name} (root={is_root})")
                        task.add_output(f"Running as {'root' if is_root else 'non-root user'}")
                        
                        # Get transport and open channel with PTY for sudo support
                        transport = ssh.get_transport()
                        channel = transport.open_session()
                        channel.get_pty()
                        channel.settimeout(10)
                        
                        # Execute reboot command
                        if is_root:
                            channel.exec_command('shutdown -r now')
                        else:
                            channel.exec_command('sudo shutdown -r now')
                        
                        # Wait briefly for command to be sent
                        time.sleep(3)
                        
                        # Try to read any output (will fail when connection drops, that's ok)
                        try:
                            output = channel.recv(1024).decode()
                            if output:
                                task.add_output(f"Reboot output: {output.strip()}")
                        except:
                            pass
                        
                        channel.close()
                        task.add_output("Reboot command sent / Reboot-Befehl gesendet")
                        
                    except Exception as e:
                        self.logger.info(f"Reboot command sent (connection closed as expected): {e}")
                        task.add_output("Reboot command sent / Reboot-Befehl gesendet")
                    finally:
                        try:
                            ssh.close()
                        except:
                            pass
                        ssh = None
                else:
                    task.add_output("[WARN] Could not reconnect for reboot / Konnte nicht für Reboot verbinden")
                    task.add_output("Trying alternative reboot method / Versuche alternative Methode...")
                    
                    # Try via Proxmox API as fallback
                    try:
                        # Proxmox has a reboot command via API
                        url = f"https://{self.config.host}:8006/api2/json/nodes/{node_name}/status"
                        response = self.session.post(url, data={'command': 'reboot'}, verify=False)
                        if response.status_code == 200:
                            task.add_output("Reboot initiated via Proxmox API")
                        else:
                            task.add_output(f"API reboot failed: {response.status_code}")
                    except Exception as api_e:
                        task.add_output(f"API reboot also failed: {api_e}")
                
                task.add_output("Waiting for node to reboot / Warte auf Neustart...")
                
                # Wait for node to come back online
                task.phase = 'wait_online'
                task.status = 'waiting_online'
                
                if self._wait_for_node_online(node_name):
                    task.add_output(f"[OK] {node_name} is back online / ist wieder online!")
                else:
                    task.add_output(f"[WARN] Timeout waiting for / beim Warten auf {node_name}")
                    task.error = "Node did not come back online in time"
            
            # Done!
            task.status = 'completed'
            task.phase = 'done'
            task.completed_at = datetime.now()
            task.add_output(f"[OK] Update completed / abgeschlossen!")
            
            # Auto-exit maintenance mode after successful update
            if node_name in self.nodes_in_maintenance:
                task.add_output(f"Exiting maintenance mode / Beende Wartungsmodus...")
                try:
                    self.exit_maintenance_mode(node_name)
                    task.add_output(f"[OK] Maintenance mode exited / Wartungsmodus beendet")
                except Exception as e:
                    task.add_output(f"[WARN] Could not exit maintenance mode / Konnte Wartungsmodus nicht beenden: {e}")
            
            self.logger.info(f"[OK] Node update completed for {node_name}")
            
        except Exception as e:
            self.logger.error(f"[ERROR] Node update failed for {node_name}: {e}")
            task.status = 'failed'
            task.error = str(e)
            task.add_output(f"[ERROR] Error / Fehler: {e}")
        
        finally:
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
    
    def get_update_status(self, node_name: str) -> Optional[Dict]:
        
        with self.update_lock:
            if node_name in self.nodes_updating:
                return self.nodes_updating[node_name].to_dict()
            return None
    
    def clear_update_status(self, node_name: str) -> bool:
        
        with self.update_lock:
            if node_name in self.nodes_updating:
                task = self.nodes_updating[node_name]
                if task.status in ['completed', 'failed']:
                    del self.nodes_updating[node_name]
                    return True
            return False
    
    # VM Control Methods
    def vm_action(self, node: str, vmid: int, vm_type: str, action: str, force: bool = False) -> Dict[str, Any]:
        # NS: start/stop/shutdown/reboot/reset - basic VM lifecycle stuff
        if not self.is_connected and not self.connect_to_proxmox():
            return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        # LXC containers don't support 'reset' - only QEMU VMs do
        if vm_type == 'lxc' and action == 'reset':
            return {'success': False, 'error': 'Reset is not supported for LXC containers. Use reboot instead.'}
        
        try:
            host = self.current_host or self.config.host
            endpoint = 'qemu' if vm_type == 'qemu' else 'lxc'
            url = f"https://{host}:8006/api2/json/nodes/{node}/{endpoint}/{vmid}/status/{action}"
            
            data = {}
            
            # MK: Force stop handling - different for QEMU vs LXC
            # Fixed 27.01.2026 - skiplock requires root@pam, removed for non-root users
            if force and action == 'stop':
                self.logger.info(f"Force stopping {vm_type}/{vmid}")
                if vm_type == 'qemu':
                    # QEMU: Use timeout=0 for immediate stop (more compatible than forceStop)
                    data['timeout'] = 0
                # LW: skiplock only works for root@pam - causes error for other users
                # "Only root may use this option" - so we skip it for non-root
                if self.config.user.lower().startswith('root@'):
                    data['skiplock'] = 1
            
            self.logger.info(f"VM Action: {action} on {vm_type}/{vmid}@{node}" + (" FORCE" if force else ""))
            resp = self._api_post(url, data=data if data else None)
            
            if resp.status_code == 200:
                self.logger.info(f"[OK] {action} on {vmid}")
                return {'success': True, 'data': resp.json().get('data')}
            else:
                self.logger.error(f"[ERROR] {resp.text}")
                return {'success': False, 'error': resp.text}
                
        except Exception as e:
            self.logger.error(f"[ERROR] vm_action: {e}")
            return {'success': False, 'error': str(e)}
    
    def clone_vm(self, node: str, vmid: int, vm_type: str, newid: int, name: str = None, 
                 full: bool = True, target_node: str = None, target_storage: str = None,
                 description: str = None) -> Dict[str, Any]:
        """clone a vm"""
        # MK: full clone = independent copy, linked clone = shares base with original
        # linked clones only work for qemu
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/clone"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/clone"
            
            data = {'newid': newid}
            
            if name:
                data['name'] = name
            
            if full:
                data['full'] = 1
            else:
                # linked clone
                if vm_type == 'qemu':
                    data['full'] = 0
                    
            # Optional target location
            if target_node:
                data['target'] = target_node
            if target_storage:
                data['storage'] = target_storage
            if description:
                data['description'] = description
            
            self.logger.info(f"Cloning {vm_type}/{vmid} to {newid} (full={full})")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info(f"[OK] Clone started: {vmid} -> {newid}")
                return {'success': True, 'data': result.get('data')}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Clone failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Clone error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_next_vmid(self) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/nextid"
            response = self._api_get(url)
            
            if response.status_code == 200:
                data = response.json()
                return {'success': True, 'vmid': int(data.get('data', 100))}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def migrate_vm_manual(self, node: str, vmid: int, vm_type: str, target_node: str, online: bool = True, options: Dict = None) -> Dict[str, Any]:
        # manual migrate
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        if options is None:
            options = {}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/migrate"
                data = {
                    'target': target_node,
                    'online': 1 if online else 0,
                }
                # Add target storage if specified
                if options.get('targetstorage'):
                    data['targetstorage'] = options['targetstorage']
                # Add with-local-disks option
                if options.get('with_local_disks'):
                    data['with-local-disks'] = 1
            else:  # lxc
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/migrate"
                data = {
                    'target': target_node,
                    'restart': 1 if online else 0,  # LXC uses restart instead of online
                }
                # Add target storage if specified
                if options.get('targetstorage'):
                    data['target-storage'] = options['targetstorage']
                # Force (for conntrack state)
                if options.get('force'):
                    data['force'] = 1
            
            self.logger.info(f"Migrating {vm_type}/{vmid} from {node} to {target_node}" + 
                           (f" (storage: {options.get('targetstorage')})" if options.get('targetstorage') else ""))
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_data = response.json()
                self.logger.info(f"[OK] Migration started for {vmid}, task: {task_data.get('data')}")
                return {'success': True, 'task': task_data.get('data')}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Migration failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Migration error: {e}")
            return {'success': False, 'error': str(e)}
    
    def remote_migrate_vm(self, node: str, vmid: int, vm_type: str, 
                          target_endpoint: str, target_storage: str, target_bridge: str,
                          target_vmid: int = None, online: bool = True, 
                          delete_source: bool = True, bwlimit: int = None) -> Dict[str, Any]:
        """cross-cluster VM migration using Proxmox remote-migrate API"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/remote_migrate"
            else:  # lxc
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/remote_migrate"
            
            # target-vmid is required - use same as source if not specified
            actual_target_vmid = target_vmid if target_vmid else vmid
            
            data = {
                'target-endpoint': target_endpoint,
                'target-vmid': actual_target_vmid,
                'target-storage': target_storage,
                'target-bridge': target_bridge,
            }
            
            if vm_type == 'qemu':
                data['online'] = 1 if online else 0
            
            if delete_source:
                data['delete'] = 1
            
            if bwlimit:
                data['bwlimit'] = bwlimit
            
            self.logger.info(f"Remote migrating {vm_type}/{vmid} from {node} to target cluster (target vmid: {actual_target_vmid})")
            self.logger.debug(f"Migration data: {data}")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_data = response.json()
                self.logger.info(f"[OK] Remote migration started for {vmid}, task: {task_data.get('data')}")
                return {'success': True, 'task': task_data.get('data')}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Remote migration failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Remote migration error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_cluster_fingerprint(self) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            import ssl
            import socket
            import hashlib
            
            # Get SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.config.host, 8006)) as sock:
                with context.wrap_socket(sock, server_hostname=self.config.host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(cert_der).hexdigest()
                    # Format as colon-separated
                    fingerprint_formatted = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
            
            return {
                'success': True, 
                'fingerprint': fingerprint_formatted,
                'host': self.config.host,
                'port': 8006
            }
        except Exception as e:
            self.logger.error(f"Error getting fingerprint: {e}")
            return {'success': False, 'error': str(e)}

    def create_api_token(self, token_name: str = 'pegaprox-migrate') -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            user = self.config.user
            
            # Create token without privilege separation (privsep=0)
            url = f"https://{host}:8006/api2/json/access/users/{user}/token/{token_name}"
            data = {
                'privsep': 0,  # No privilege separation - token has same permissions as user
                'expire': 0,   # No expiration (we'll delete it manually)
                'comment': 'PegaProx temporary migration token'
            }
            
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                result = response.json()
                token_data = result.get('data', {})
                token_value = token_data.get('value', '')
                full_token_id = token_data.get('full-tokenid', f"{user}!{token_name}")
                
                self.logger.info(f"[OK] Created API token: {full_token_id}")
                return {
                    'success': True,
                    'token_id': full_token_id,
                    'token_value': token_value,
                    'token_name': token_name
                }
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Failed to create API token: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Error creating API token: {e}")
            return {'success': False, 'error': str(e)}

    def delete_api_token(self, token_name: str = 'pegaprox-migrate') -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            user = self.config.user
            
            url = f"https://{host}:8006/api2/json/access/users/{user}/token/{token_name}"
            response = self._api_delete(url)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Deleted API token: {user}!{token_name}")
                return {'success': True}
            else:
                error_msg = response.text
                self.logger.warning(f"[WARN] Failed to delete API token: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Error deleting API token: {e}")
            return {'success': False, 'error': str(e)}

    def delete_vm(self, node: str, vmid: int, vm_type: str, purge: bool = False, destroy_unreferenced: bool = False) -> Dict[str, Any]:
        """NS: Feb 2026 - Fixed: now sanitizes boot order before delete and waits for task completion (fixes #79)"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}

        try:
            # First check if VM is running and stop it
            if vm_type == 'qemu':
                status_url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/current"
            else:
                status_url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/status/current"

            status_response = self._create_session().get(status_url, timeout=15)
            if status_response.status_code == 200:
                status = status_response.json()['data'].get('status')
                if status == 'running':
                    self.logger.info(f"Stopping {vm_type}/{vmid} before deletion")
                    if vm_type == 'qemu':
                        stop_url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/stop"
                    else:
                        stop_url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/status/stop"
                    stop_resp = self._create_session().post(stop_url, timeout=15)
                    # NS: Wait for stop task to finish instead of fixed 3s sleep
                    if stop_resp.status_code == 200:
                        stop_task = stop_resp.json().get('data', '')
                        if stop_task:
                            self._wait_for_task(node, stop_task, timeout=30)
                        else:
                            import time
                            time.sleep(3)
                    else:
                        import time
                        time.sleep(3)

            # NS: Feb 2026 - Sanitize boot order before deletion to prevent
            # "storage volume does not exist" errors when Proxmox tries to cleanup
            # disks that are referenced in boot order but no longer available
            try:
                sanitize_result = self.sanitize_boot_order(node, vmid, vm_type)
                if sanitize_result.get('changed'):
                    self.logger.info(f"[DELETE] Sanitized boot order before deleting {vm_type}/{vmid}: removed {sanitize_result.get('removed', [])}")
            except Exception as e:
                self.logger.warning(f"[DELETE] Boot order sanitize failed (continuing): {e}")

            # Now delete
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}"

            params = {}
            if purge:
                params['purge'] = 1
            if destroy_unreferenced and vm_type == 'qemu':
                params['destroy-unreferenced-disks'] = 1

            self.logger.info(f"Deleting {vm_type}/{vmid} on {node} with params: {params}")
            response = self._create_session().delete(url, params=params)

            if response.status_code == 200:
                task_data = response.json()
                task_upid = task_data.get('data', '')
                self.logger.info(f"[DELETE] {vm_type}/{vmid} delete task started: {task_upid}")

                # NS: Feb 2026 - Wait for the actual deletion task to complete (fixes #79)
                # Previously returned success immediately without checking if Proxmox actually deleted the VM
                task_ok = True
                if task_upid:
                    task_ok = self._wait_for_task(node, task_upid, timeout=120)
                    if not task_ok:
                        # Task failed - get the error details from task log
                        error_detail = f'Proxmox deletion task failed for {vm_type}/{vmid}'
                        try:
                            log_url = f"https://{self.host}:8006/api2/json/nodes/{node}/tasks/{task_upid}/log?limit=10"
                            log_resp = self._api_get(log_url)
                            if log_resp.status_code == 200:
                                log_lines = log_resp.json().get('data', [])
                                error_lines = [l.get('t', '') for l in log_lines if 'error' in l.get('t', '').lower() or 'WARN' in l.get('t', '') or 'failed' in l.get('t', '').lower()]
                                if error_lines:
                                    error_detail = '; '.join(error_lines[-3:])  # Last 3 error lines
                        except Exception:
                            pass
                        self.logger.error(f"[ERROR] Deletion task failed: {error_detail}")
                        return {'success': False, 'error': error_detail, 'task': task_upid}

                self.logger.info(f"[OK] {vm_type}/{vmid} successfully deleted")

                # MK: Cleanup - remove VM from balancing exclusion list
                try:
                    db = get_db()
                    cursor = db.conn.cursor()
                    cursor.execute(
                        'DELETE FROM balancing_excluded_vms WHERE cluster_id = ? AND vmid = ?',
                        (self.id, vmid)
                    )
                    if cursor.rowcount > 0:
                        self.logger.info(f"Removed VM {vmid} from balancing exclusion list")
                    db.conn.commit()
                except Exception as cleanup_err:
                    self.logger.warning(f"Failed to cleanup balancing exclusion for VM {vmid}: {cleanup_err}")

                return {'success': True, 'task': task_upid}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Deletion failed: {error_msg}")
                return {'success': False, 'error': error_msg}

        except Exception as e:
            self.logger.error(f"[ERROR] Deletion error: {e}")
            return {'success': False, 'error': str(e)}

    # NOTE: get_next_vmid is defined earlier in this class (line ~3989)
    # Removed duplicate definition here - NS Jan 2026
    
    def get_templates(self, node: str) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        templates = []
        try:
            # Get VM templates
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu"
            response = self._api_get(url)
            if response.status_code == 200:
                for vm in response.json()['data']:
                    if vm.get('template'):
                        templates.append({
                            'type': 'qemu',
                            'vmid': vm['vmid'],
                            'name': vm.get('name', f"VM {vm['vmid']}"),
                        })
            
            # Get CT templates from storage
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/storage"
            storage_response = self._api_get(url)
            if storage_response.status_code == 200:
                for storage in storage_response.json()['data']:
                    if 'vztmpl' in storage.get('content', ''):
                        tmpl_url = f"https://{self.host}:8006/api2/json/nodes/{node}/storage/{storage['storage']}/content"
                        tmpl_response = self._create_session().get(tmpl_url, params={'content': 'vztmpl'})
                        if tmpl_response.status_code == 200:
                            for tmpl in tmpl_response.json()['data']:
                                templates.append({
                                    'type': 'lxc',
                                    'volid': tmpl['volid'],
                                    'name': tmpl.get('volid', '').split('/')[-1],
                                })
        except Exception as e:
            self.logger.error(f"Error getting templates: {e}")
        
        return templates
    
    def create_vm(self, node: str, vm_config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu"
            
            # Required fields
            vmid = vm_config.get('vmid')
            if not vmid:
                next_id = self.get_next_vmid()
                if not next_id['success']:
                    return next_id
                vmid = next_id['vmid']
            
            data = {
                'vmid': vmid,
                'name': vm_config.get('name', f'vm-{vmid}'),
                'memory': vm_config.get('memory', 2048),
                'cores': vm_config.get('cores', 2),
                'sockets': vm_config.get('sockets', 1),
            }
            
            # CPU
            if vm_config.get('cpu'):
                data['cpu'] = vm_config['cpu']
            
            # MK: CPU Affinity
            if vm_config.get('cpu_affinity'):
                data['affinity'] = vm_config['cpu_affinity']
            
            # MK: NUMA
            if vm_config.get('numa'):
                data['numa'] = '1'
            
            # MK: Advanced Memory - Ballooning
            if vm_config.get('min_memory'):
                data['balloon'] = vm_config['min_memory']
            elif vm_config.get('ballooning') is False:
                data['balloon'] = '0'  # Disable ballooning
            
            # MK: Memory Shares
            if vm_config.get('shares'):
                data['shares'] = vm_config['shares']
            
            # BIOS
            if vm_config.get('bios'):
                data['bios'] = vm_config['bios']
            
            # OS Type
            if vm_config.get('ostype'):
                data['ostype'] = vm_config['ostype']
            
            # Machine type - Proxmox expects format: type=<machine> or just pc/q35
            if vm_config.get('machine'):
                machine = vm_config['machine']
                # Proxmox 8+ expects the machine type directly without 'type=' prefix
                # Valid values: pc, q35, pc-i440fx-*, pc-q35-*, etc.
                if machine in ['i440fx', 'pc']:
                    data['machine'] = 'pc'
                elif machine == 'q35':
                    data['machine'] = 'q35'
                else:
                    data['machine'] = machine
            
            # Storage/Disk with enhanced options
            storage = vm_config.get('storage', 'local-lvm')
            disk_size = vm_config.get('disk_size', '32')
            # Remove G suffix if present - Proxmox API expects just the number
            disk_size = str(disk_size).replace('G', '').replace('g', '')
            
            disk_type = vm_config.get('disk_type', 'scsi')
            disk_format = vm_config.get('disk_format', '')  # raw, qcow2, vmdk
            scsi_hw = vm_config.get('scsihw', 'virtio-scsi-pci')
            
            # Build disk string - format depends on storage type
            # For LVM/ZFS: storage:size (e.g., local-lvm:32)
            # For directory: storage:size,format=X (e.g., local:32,format=qcow2)
            disk_str = f"{storage}:{disk_size}"
            
            # Add disk options
            disk_options = []
            
            # Add format if specified (needed for directory-based storage)
            if disk_format:
                disk_options.append(f"format={disk_format}")
            
            if vm_config.get('disk_cache'):
                disk_options.append(f"cache={vm_config['disk_cache']}")
            if vm_config.get('disk_discard'):
                disk_options.append("discard=on")
            if vm_config.get('disk_iothread') and disk_type == 'scsi':
                disk_options.append("iothread=1")
            if vm_config.get('disk_ssd'):
                disk_options.append("ssd=1")
            
            if disk_options:
                disk_str += "," + ",".join(disk_options)
            
            # Set disk based on type
            if disk_type == 'scsi':
                data['scsihw'] = scsi_hw
                data['scsi0'] = disk_str
            elif disk_type == 'virtio':
                data['virtio0'] = disk_str
            elif disk_type == 'ide':
                data['ide0'] = disk_str
            elif disk_type == 'sata':
                data['sata0'] = disk_str
            
            # MK: Additional Disks
            additional_disks = vm_config.get('additional_disks', [])
            disk_counters = {'scsi': 1, 'virtio': 1, 'sata': 1}  # Start at 1, 0 is primary
            for add_disk in additional_disks:
                add_type = add_disk.get('type', 'scsi')
                add_storage = add_disk.get('storage', storage)
                add_size = str(add_disk.get('size', '32')).replace('G', '').replace('g', '')
                add_disk_str = f"{add_storage}:{add_size}"
                
                # MK: Use per-disk options - each disk has its own format, cache, discard, iothread, ssd
                add_opts = []
                
                # Format: per-disk only (no fallback to global)
                add_format = add_disk.get('format', '')
                if add_format:
                    add_opts.append(f"format={add_format}")
                
                # Cache: per-disk only
                add_cache = add_disk.get('cache', '')
                if add_cache:
                    add_opts.append(f"cache={add_cache}")
                
                # Discard: per-disk (defaults to true in UI)
                if add_disk.get('discard', True):
                    add_opts.append("discard=on")
                
                # IO Thread for SCSI: per-disk (defaults to true in UI)
                if add_disk.get('iothread', True) and add_type == 'scsi':
                    add_opts.append("iothread=1")
                
                # SSD emulation: per-disk
                if add_disk.get('ssd', False):
                    add_opts.append("ssd=1")
                
                if add_opts:
                    add_disk_str += "," + ",".join(add_opts)
                
                disk_idx = disk_counters.get(add_type, 1)
                data[f"{add_type}{disk_idx}"] = add_disk_str
                disk_counters[add_type] = disk_idx + 1
                
                # MK: If this disk uses a different SCSI controller, note it (Proxmox only allows one scsihw though)
                # The per-disk scsihw is mostly for UI consistency; Proxmox uses one controller for all SCSI disks
            
            # EFI disk for UEFI
            if vm_config.get('bios') == 'ovmf':
                efi_storage = vm_config.get('efi_storage', storage)
                efi_type = "4m"
                if vm_config.get('efi_pre_enroll'):
                    data['efidisk0'] = f"{efi_storage}:1,efitype={efi_type},pre-enrolled-keys=1"
                else:
                    data['efidisk0'] = f"{efi_storage}:1,efitype={efi_type}"
                # UEFI requires q35 machine type
                if not vm_config.get('machine') or vm_config.get('machine') in ['i440fx', 'pc']:
                    data['machine'] = 'q35'
            
            # TPM
            if vm_config.get('tpm_storage'):
                tpm_version = vm_config.get('tpm_version', 'v2.0')
                data['tpmstate0'] = f"{vm_config['tpm_storage']}:1,version={tpm_version}"
            
            # Network
            net_model = vm_config.get('net_model', 'virtio')
            net_bridge = vm_config.get('net_bridge', 'vmbr0')
            net_str = f"{net_model},bridge={net_bridge}"
            if vm_config.get('net_firewall'):
                net_str += ",firewall=1"
            if vm_config.get('net_tag'):
                net_str += f",tag={vm_config['net_tag']}"
            # MK: MAC Address
            if vm_config.get('net_macaddr'):
                net_str += f",macaddr={vm_config['net_macaddr']}"
            # MK: MTU
            if vm_config.get('net_mtu'):
                net_str += f",mtu={vm_config['net_mtu']}"
            # MK: Rate Limit (MB/s -> Proxmox uses MB/s directly)
            if vm_config.get('net_rate'):
                net_str += f",rate={vm_config['net_rate']}"
            # MK: Disconnect (link_down)
            if vm_config.get('net_disconnect'):
                net_str += ",link_down=1"
            data['net0'] = net_str
            
            # CD-ROM / ISO
            boot_order = []
            
            # MK: Only add disk to boot order if it was actually created
            if disk_type == 'scsi' and 'scsi0' in data:
                boot_order.append('scsi0')
            elif disk_type == 'virtio' and 'virtio0' in data:
                boot_order.append('virtio0')
            elif disk_type == 'ide' and 'ide0' in data:
                boot_order.append('ide0')
            elif disk_type == 'sata' and 'sata0' in data:
                boot_order.append('sata0')
            
            if vm_config.get('iso'):
                data['ide2'] = f"{vm_config['iso']},media=cdrom"
                boot_order.append('ide2')
            
            # VirtIO drivers ISO for Windows (secondary CD-ROM)
            if vm_config.get('virtio_iso'):
                data['ide3'] = f"{vm_config['virtio_iso']},media=cdrom"
            
            boot_order.append('net0')
            data['boot'] = 'order=' + ';'.join(boot_order)
            
            # VGA
            if vm_config.get('vga'):
                data['vga'] = vm_config['vga']
            
            # QEMU Agent
            if vm_config.get('agent'):
                data['agent'] = '1'
            
            # Start on boot
            if vm_config.get('onboot'):
                data['onboot'] = '1'
            
            # Start after creation
            start_after = vm_config.get('start', False)
            
            # MK: HA config (will be applied after VM creation)
            ha_enabled = vm_config.get('ha_enabled', False)
            ha_group = vm_config.get('ha_group', '')
            
            self.logger.info(f"Creating VM {vmid} on {node} with config: {data}")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_data = response.json()
                self.logger.info(f"[OK] VM {vmid} created, task: {task_data.get('data')}")
                
                # MK: Add to HA if enabled
                if ha_enabled:
                    try:
                        ha_url = f"https://{self.host}:8006/api2/json/cluster/ha/resources"
                        ha_data = {'sid': f"vm:{vmid}"}
                        if ha_group:
                            ha_data['group'] = ha_group
                        ha_response = self._api_post(ha_url, data=ha_data)
                        if ha_response.status_code == 200:
                            self.logger.info(f"[OK] VM {vmid} added to HA")
                        else:
                            self.logger.warning(f"[WARN] Failed to add VM {vmid} to HA: {ha_response.text}")
                    except Exception as ha_err:
                        self.logger.warning(f"[WARN] HA config failed: {ha_err}")
                
                return {'success': True, 'vmid': vmid, 'task': task_data.get('data')}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] VM creation failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] VM creation error: {e}")
            return {'success': False, 'error': str(e)}
    
    
    def create_container(self, node: str, ct_config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc"
            
            # Required fields
            vmid = ct_config.get('vmid')
            if not vmid:
                next_id = self.get_next_vmid()
                if not next_id['success']:
                    return next_id
                vmid = next_id['vmid']
            
            # Template is required for CT creation
            template = ct_config.get('template')
            if not template:
                return {'success': False, 'error': 'Template is required for container creation'}
            
            # Build data payload
            # MK: defaults are conservative, users can change later
            data = {
                'vmid': vmid,
                'hostname': ct_config.get('hostname', ct_config.get('name', f'ct-{vmid}')),
                'ostemplate': template,
                'memory': ct_config.get('memory', 512),  # MB
                'swap': ct_config.get('swap', 512),
                'cores': ct_config.get('cores', 1),
                'password': ct_config.get('password', 'changeme'),  # should probably require this
            }
            
            # Root disk
            storage = ct_config.get('storage', 'local-lvm')
            disk_size = ct_config.get('disk_size', '8')  # GB
            data['rootfs'] = f"{storage}:{disk_size}"
            
            # MK: Additional Mount Points
            additional_disks = ct_config.get('additional_disks', [])
            for idx, mp in enumerate(additional_disks):
                mp_storage = mp.get('storage', storage)
                mp_size = str(mp.get('size', '8')).replace('G', '').replace('g', '')
                mp_path = mp.get('path', f'/mnt/data{idx}')
                # Format: storage:size,mp=/path
                data[f'mp{idx}'] = f"{mp_storage}:{mp_size},mp={mp_path}"
            
            # Network configuration
            # NS: this networking stuff is confusing, proxmox docs are not great
            net_bridge = ct_config.get('net_bridge', 'vmbr0')
            net_str = f"name=eth0,bridge={net_bridge}"
            
            # IPv4 configuration
            net_ip_type = ct_config.get('net_ip_type', 'dhcp')
            if net_ip_type == 'dhcp':
                net_str += ",ip=dhcp"
            elif net_ip_type == 'static':
                net_ip = ct_config.get('net_ip', '')
                if net_ip:
                    net_str += f",ip={net_ip}"
                    if ct_config.get('net_gw'):
                        net_str += f",gw={ct_config['net_gw']}"
            # 'manual' = no ip config
            
            # IPv6 configuration
            net_ip6_type = ct_config.get('net_ip6_type', 'dhcp')
            if net_ip6_type == 'dhcp':
                net_str += ",ip6=dhcp"
            elif net_ip6_type == 'slaac':
                net_str += ",ip6=auto"
            elif net_ip6_type == 'static':
                net_ip6 = ct_config.get('net_ip6', '')
                if net_ip6:
                    net_str += f",ip6={net_ip6}"
                    if ct_config.get('net_gw6'):
                        net_str += f",gw6={ct_config['net_gw6']}"
            # 'manual' = no ip6 config
            
            # VLAN tag
            if ct_config.get('net_tag'):
                net_str += f",tag={ct_config['net_tag']}"
            
            # Firewall
            if ct_config.get('net_firewall'):
                net_str += ",firewall=1"
            
            # Disconnected
            if ct_config.get('net_disconnected'):
                net_str += ",link_down=1"
            
            # MK: MAC Address
            if ct_config.get('net_macaddr'):
                net_str += f",hwaddr={ct_config['net_macaddr']}"
            
            # MK: MTU
            if ct_config.get('net_mtu'):
                net_str += f",mtu={ct_config['net_mtu']}"
            
            # MK: Rate Limit (MB/s)
            if ct_config.get('net_rate'):
                net_str += f",rate={ct_config['net_rate']}"
            
            data['net0'] = net_str
            
            # DNS settings
            if ct_config.get('dns_domain'):
                data['searchdomain'] = ct_config['dns_domain']
            if ct_config.get('dns_servers'):
                data['nameserver'] = ct_config['dns_servers']
            
            # Unprivileged
            if ct_config.get('unprivileged', True):
                data['unprivileged'] = '1'
            
            # Start on boot
            if ct_config.get('onboot'):
                data['onboot'] = '1'
            
            # SSH public keys
            ssh_keys = ct_config.get('ssh_public_keys') or ct_config.get('ssh_key')
            if ssh_keys:
                data['ssh-public-keys'] = ssh_keys
            
            # Features (nesting, etc.)
            features = []
            if ct_config.get('nesting'):
                features.append('nesting=1')
            if features:
                data['features'] = ','.join(features)
            
            # MK: HA config (will be applied after CT creation)
            ha_enabled = ct_config.get('ha_enabled', False)
            ha_group = ct_config.get('ha_group', '')
            
            self.logger.info(f"Creating container {vmid} on {node}")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_data = response.json()
                self.logger.info(f"[OK] Container {vmid} created, task: {task_data.get('data')}")
                
                # MK: Add to HA if enabled
                if ha_enabled:
                    try:
                        ha_url = f"https://{self.host}:8006/api2/json/cluster/ha/resources"
                        ha_data = {'sid': f"ct:{vmid}"}
                        if ha_group:
                            ha_data['group'] = ha_group
                        ha_response = self._api_post(ha_url, data=ha_data)
                        if ha_response.status_code == 200:
                            self.logger.info(f"[OK] Container {vmid} added to HA")
                        else:
                            self.logger.warning(f"[WARN] Failed to add CT {vmid} to HA: {ha_response.text}")
                    except Exception as ha_err:
                        self.logger.warning(f"[WARN] HA config failed: {ha_err}")
                
                return {'success': True, 'vmid': vmid, 'task': task_data.get('data')}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Container creation failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Container creation error: {e}")
            return {'success': False, 'error': str(e)}
    
    # ==================== SNAPSHOT METHODS ====================
    
    def get_snapshots(self, node: str, vmid: int, vm_type: str) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/snapshot"
            else:
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/snapshot"
            
            response = self._api_get(url)
            
            if response.status_code == 200:
                snapshots = response.json()['data']
                # Sort by snaptime, filter out 'current'
                return sorted(
                    [s for s in snapshots if s.get('name') != 'current'],
                    key=lambda x: x.get('snaptime', 0),
                    reverse=True
                )
            return []
        except Exception as e:
            self.logger.error(f"Error getting snapshots: {e}")
            return []
    
    def check_snapshot_capability(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'can_snapshot': False, 'reason': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            
            # Get VM/CT config
            if vm_type == 'qemu':
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            response = self._create_session().get(config_url, timeout=15)
            if response.status_code != 200:
                return {'can_snapshot': False, 'reason': 'Could not get VM configuration'}
            
            config = response.json().get('data', {})
            issues = []
            
            if vm_type == 'qemu':
                # Check for issues that prevent QEMU snapshots
                for key, value in config.items():
                    if key.startswith('scsi') or key.startswith('virtio') or key.startswith('ide') or key.startswith('sata'):
                        if isinstance(value, str):
                            # Check for raw format (no snapshots)
                            if ',format=raw' in value or value.endswith(':raw'):
                                issues.append(f"Disk {key} uses raw format (no snapshots)")
                            # Check for passthrough devices
                            if '/dev/' in value:
                                issues.append(f"Disk {key} is a passthrough device")
                            # Check for iscsi without snapshots
                            if 'iscsi:' in value.lower():
                                issues.append(f"Disk {key} is iSCSI (may not support snapshots)")
                    
                    # Check for PCI passthrough
                    if key.startswith('hostpci'):
                        issues.append(f"PCI passthrough device {key} prevents live snapshots with RAM")
                    
                    # Check for USB passthrough  
                    if key.startswith('usb') and '/dev/' in str(value):
                        issues.append(f"USB passthrough {key} may affect snapshots")
                
                # check EFI disk exists without proper storage
                if 'efidisk0' in config:
                    efi_disk = config['efidisk0']
                    if isinstance(efi_disk, str) and 'raw' in efi_disk.lower():
                        issues.append("EFI disk uses raw format")
            
            else:  # LXC container
                # Check for bind mounts
                for key, value in config.items():
                    if key.startswith('mp') and isinstance(value, str):
                        if ',bind' in value or 'bind=' in value:
                            issues.append(f"Mount point {key} is a bind mount (excluded from snapshots)")
                
                # Check rootfs
                rootfs = config.get('rootfs', '')
                if isinstance(rootfs, str):
                    if 'dir:' in rootfs.lower() or 'nfs:' in rootfs.lower():
                        issues.append("Container uses directory or NFS storage (limited snapshot support)")
            
            if issues:
                result = {
                    'can_snapshot': True,  # Usually still possible, just with limitations
                    'warnings': issues,
                    'reason': '; '.join(issues)
                }
                try:
                    result['efficient_snapshot'] = self.check_efficient_snapshot_capability(node, vmid, vm_type)
                except Exception:
                    result['efficient_snapshot'] = {'eligible': False}
                return result
            
            result = {'can_snapshot': True, 'warnings': [], 'reason': None}
            # NS: Feb 2026 - Add efficient snapshot capability info
            try:
                result['efficient_snapshot'] = self.check_efficient_snapshot_capability(node, vmid, vm_type)
            except Exception:
                result['efficient_snapshot'] = {'eligible': False}
            return result

        except Exception as e:
            self.logger.error(f"Error checking snapshot capability: {e}")
            return {'can_snapshot': False, 'reason': str(e)}
    
    def create_snapshot(self, node: str, vmid: int, vm_type: str, snapname: str, description: str = '', vmstate: bool = False) -> Dict[str, Any]:
        """create a snapshot"""
        # LW: this was surprisingly annoying to get right
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/snapshot"
            else:
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/snapshot"
            
            data = {'snapname': snapname}
            if description:
                data['description'] = description
            if vmstate and vm_type == 'qemu':
                data['vmstate'] = 1  # include RAM
            
            # self.logger.info(f"creating snapshot {snapname}")  # DEBUG
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_data = response.json()
                return {'success': True, 'task': task_data.get('data')}
            else:
                # try to parse error msg
                error_text = response.text
                try:
                    error_json = response.json()
                    if 'errors' in error_json:
                        error_text = str(error_json['errors'])
                    elif 'data' in error_json:
                        error_text = str(error_json['data'])
                except:
                    pass
                
                # make error messages nicer
                if 'not supported' in error_text.lower():
                    error_text = 'Snapshots are not supported for this storage type'
                elif 'running' in error_text.lower() and 'vmstate' in error_text.lower():
                    error_text = 'Cannot create RAM snapshot: VM has PCI passthrough or other incompatible devices'
                elif 'lock' in error_text.lower():
                    error_text = 'VM is locked (another operation in progress)'
                
                return {'success': False, 'error': error_text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_snapshot(self, node: str, vmid: int, vm_type: str, snapname: str) -> Dict[str, Any]:
        """delete snapshot"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}"
            
            # self.logger.info(f"deleting snapshot {snapname}")  # spammy
            response = self._api_delete(url)
            
            if response.status_code == 200:
                task_data = response.json()
                return {'success': True, 'task': task_data.get('data')}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def rollback_snapshot(self, node: str, vmid: int, vm_type: str, snapname: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback"
            
            self.logger.info(f"Rolling back {vm_type}/{vmid} to snapshot '{snapname}'")
            response = self._create_session().post(url, timeout=15)
            
            if response.status_code == 200:
                task_data = response.json()
                return {'success': True, 'task': task_data.get('data')}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ==================== EFFICIENT (LVM COW) SNAPSHOT METHODS ====================
    # NS: Feb 2026 - Space-efficient LVM snapshots for shared storage (iSCSI SAN)
    # These create small COW snapshots via SSH lvcreate -s instead of full Proxmox snapshots

    def _node_ssh_exec(self, node: str, command: str, timeout: int = 30) -> tuple:
        """Run SSH command on a specific Proxmox node, returns (exit_code, stdout, stderr)"""
        node_ip = self._get_node_ip(node)
        if not node_ip:
            return -1, '', f'Cannot resolve IP for node {node}'

        ssh = self._ssh_connect(node_ip)
        if not ssh:
            return -1, '', f'SSH connection to {node} ({node_ip}) failed'

        try:
            return self._ssh_execute(ssh, command)
        finally:
            try:
                ssh.close()
            except:
                pass

    def _get_vm_lvm_disks(self, node: str, vmid: int, vm_type: str) -> list:
        """Parse VM config, find disks on shared LVM storage.
        Returns list of dicts: [{disk_key, storage_name, lv_name, vg_name, size_gb}]
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []

        try:
            host = self.current_host or self.config.host

            # Get VM config
            if vm_type == 'qemu':
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"

            response = self._create_session().get(config_url, timeout=15)
            if response.status_code != 200:
                return []
            config = response.json().get('data', {})

            # Get storage configs
            storage_url = f"https://{host}:8006/api2/json/storage"
            storage_response = self._create_session().get(storage_url, timeout=10)
            storage_configs = {}
            if storage_response.status_code == 200:
                for s in storage_response.json().get('data', []):
                    storage_configs[s['storage']] = s

            lvm_disks = []
            # Disk key prefixes by vm_type
            if vm_type == 'qemu':
                prefixes = ('scsi', 'virtio', 'ide', 'sata')
            else:
                prefixes = ('rootfs', 'mp')

            for key, value in config.items():
                is_disk = False
                if vm_type == 'qemu':
                    is_disk = any(key.startswith(p) and (key[len(p):].isdigit() or key == p) for p in prefixes)
                else:
                    is_disk = key == 'rootfs' or (key.startswith('mp') and key[2:].isdigit())

                if not is_disk or not isinstance(value, str) or ':' not in value:
                    continue

                storage_name = value.split(':')[0]
                storage_cfg = storage_configs.get(storage_name, {})

                # Only shared LVM storage
                if storage_cfg.get('type') != 'lvm':
                    continue
                if not storage_cfg.get('shared', 0):
                    continue

                vg_name = storage_cfg.get('vgname', '')
                if not vg_name:
                    continue

                # Extract LV name: "iscsi-lvm:vm-100-disk-0,size=100G" -> "vm-100-disk-0"
                disk_part = value.split(':')[1].split(',')[0]

                # Extract size from config value
                size_gb = 0.0
                for part in value.split(','):
                    if part.startswith('size='):
                        size_str = part[5:].upper().strip()
                        if size_str.endswith('G'):
                            size_gb = float(size_str[:-1])
                        elif size_str.endswith('T'):
                            size_gb = float(size_str[:-1]) * 1024
                        elif size_str.endswith('M'):
                            size_gb = float(size_str[:-1]) / 1024

                lvm_disks.append({
                    'disk_key': key,
                    'storage_name': storage_name,
                    'lv_name': disk_part,
                    'vg_name': vg_name,
                    'size_gb': size_gb
                })

            return lvm_disks

        except Exception as e:
            self.logger.error(f"Error getting LVM disks for {vm_type}/{vmid}: {e}")
            return []

    def check_efficient_snapshot_capability(self, node: str, vmid: int, vm_type: str) -> dict:
        """check if VM supports space-efficient LVM snapshots"""
        result = {
            'eligible': False,
            'lvm_disks': [],
            'vg_name': '',
            'vg_free_gb': 0.0,
            'total_disk_size_gb': 0.0,
            'recommended_snap_size_gb': 0.0,
            'savings_percent': 0,
            'has_guest_agent': False,
            'warnings': []
        }

        try:
            lvm_disks = self._get_vm_lvm_disks(node, vmid, vm_type)
            if not lvm_disks:
                return result

            result['lvm_disks'] = lvm_disks
            vg_name = lvm_disks[0]['vg_name']
            result['vg_name'] = vg_name

            total_size = sum(d['size_gb'] for d in lvm_disks)
            result['total_disk_size_gb'] = total_size

            # Get VG free space via SSH
            exit_code, stdout, stderr = self._node_ssh_exec(
                node, f'vgs --noheadings --nosuffix --units g -o vg_free {shlex.quote(vg_name)}'
            )
            if exit_code == 0 and stdout.strip():
                try:
                    result['vg_free_gb'] = float(stdout.strip())
                except ValueError:
                    result['warnings'].append('Could not parse VG free space')

            # Recommend 10% of total disk size
            recommended = round(max(1.0, total_size * 0.10), 1)
            result['recommended_snap_size_gb'] = recommended

            if total_size > 0:
                result['savings_percent'] = round((1 - recommended / total_size) * 100)

            # Check existing efficient snapshot count
            db = get_db()
            existing = db.get_efficient_snapshots(self.id, vmid)
            if len(existing) >= 5:
                result['warnings'].append('Maximum of 5 efficient snapshots reached')
                return result

            # Check VG has enough space (recommended + 2GB buffer)
            if result['vg_free_gb'] < recommended + 2:
                result['warnings'].append(f"Not enough VG free space ({result['vg_free_gb']:.1f} GB free, need {recommended + 2:.1f} GB)")
                return result

            # Check guest agent availability (QEMU only)
            if vm_type == 'qemu':
                try:
                    host = self.current_host or self.config.host
                    config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                    resp = self._create_session().get(config_url, timeout=10)
                    if resp.status_code == 200:
                        config = resp.json().get('data', {})
                        result['has_guest_agent'] = bool(config.get('agent', 0))
                except:
                    pass

            result['eligible'] = True
            return result

        except Exception as e:
            self.logger.error(f"Error checking efficient snapshot capability: {e}")
            result['warnings'].append(str(e))
            return result

    def create_efficient_snapshot(self, node: str, vmid: int, vm_type: str,
                                  snapname: str, description: str = '',
                                  snap_size_gb: float = None) -> dict:
        """Create space-efficient LVM COW snapshots for all VM disks.

        NS: Feb 2026 - Core creation flow:
        1. Check capability + VG free space
        2. Sanitize snapname
        3. Optionally freeze guest FS
        4. lvcreate -s for each disk
        5. Rollback on partial failure
        6. Save to DB
        """
        # Sanitize snapname
        snapname = re.sub(r'[^a-zA-Z0-9_-]', '', snapname)
        if not snapname:
            return {'success': False, 'error': 'Invalid snapshot name'}

        # Check capability
        cap = self.check_efficient_snapshot_capability(node, vmid, vm_type)
        if not cap['eligible']:
            reason = cap['warnings'][0] if cap['warnings'] else 'VM not eligible for efficient snapshots'
            return {'success': False, 'error': reason}

        lvm_disks = cap['lvm_disks']
        vg_name = cap['vg_name']

        # Check duplicate name
        db = get_db()
        existing = db.get_efficient_snapshots(self.id, vmid)
        for s in existing:
            if s['snapname'] == snapname:
                return {'success': False, 'error': f"Snapshot name '{snapname}' already exists"}

        # Calculate per-disk snapshot size
        if snap_size_gb is None:
            snap_size_gb = cap['recommended_snap_size_gb']
        total_disk_size = cap['total_disk_size_gb']
        per_disk_sizes = []
        for d in lvm_disks:
            if total_disk_size > 0:
                ratio = d['size_gb'] / total_disk_size
            else:
                ratio = 1.0 / len(lvm_disks)
            per_disk_sizes.append(max(1.0, round(snap_size_gb * ratio, 1)))

        # Check VG has enough free space
        total_alloc = sum(per_disk_sizes)
        if cap['vg_free_gb'] < total_alloc + 2:
            return {'success': False, 'error': f"Not enough VG space: {cap['vg_free_gb']:.1f} GB free, need {total_alloc + 2:.1f} GB"}

        # Try to freeze guest filesystem (QEMU with agent only)
        fs_frozen = False
        if vm_type == 'qemu' and cap.get('has_guest_agent'):
            try:
                host = self.current_host or self.config.host
                freeze_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/fsfreeze-freeze"
                resp = self._create_session().post(freeze_url, timeout=30)
                if resp.status_code == 200:
                    fs_frozen = True
                    self.logger.info(f"FS frozen for {vm_type}/{vmid}")
            except Exception as e:
                self.logger.warning(f"FS freeze failed for {vm_type}/{vmid}, proceeding without: {e}")

        created_lvs = []
        disk_records = []
        try:
            for i, disk in enumerate(lvm_disks):
                snap_lv = f"{disk['lv_name']}-snap-{snapname}"
                alloc_gb = per_disk_sizes[i]

                exit_code, stdout, stderr = self._node_ssh_exec(
                    node,
                    f"lvcreate -s -L {alloc_gb:.0f}G -n {shlex.quote(snap_lv)} /dev/{shlex.quote(vg_name)}/{shlex.quote(disk['lv_name'])}"
                )

                if exit_code != 0:
                    error_msg = stderr or stdout or 'lvcreate failed'
                    raise RuntimeError(f"Failed to create snapshot LV for {disk['disk_key']}: {error_msg}")

                created_lvs.append(snap_lv)
                disk_records.append({
                    'disk_key': disk['disk_key'],
                    'original_lv': disk['lv_name'],
                    'snap_lv': snap_lv,
                    'disk_size_gb': disk['size_gb'],
                    'snap_alloc_gb': alloc_gb,
                    'snap_used_percent': 0.0
                })

        except Exception as e:
            # Rollback: remove already-created LVs
            for lv in created_lvs:
                try:
                    self._node_ssh_exec(node, f"lvremove -y /dev/{shlex.quote(vg_name)}/{shlex.quote(lv)}")
                    self.logger.info(f"Rolled back snapshot LV: {lv}")
                except:
                    pass
            return {'success': False, 'error': str(e)}

        finally:
            # Always thaw if we froze
            if fs_frozen:
                try:
                    host = self.current_host or self.config.host
                    thaw_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/fsfreeze-thaw"
                    self._create_session().post(thaw_url, timeout=30)
                    self.logger.info(f"FS thawed for {vm_type}/{vmid}")
                except Exception as e:
                    self.logger.error(f"FS thaw failed for {vm_type}/{vmid}: {e}")

        # Save to DB
        snap_id = str(uuid.uuid4())
        total_alloc = sum(d['snap_alloc_gb'] for d in disk_records)
        db.save_efficient_snapshot({
            'id': snap_id,
            'cluster_id': self.id,
            'node': node,
            'vmid': vmid,
            'vm_type': vm_type,
            'snapname': snapname,
            'description': description,
            'vg_name': vg_name,
            'disks': disk_records,
            'total_disk_size_gb': total_disk_size,
            'total_snap_alloc_gb': total_alloc,
            'fs_frozen': fs_frozen,
            'status': 'active',
            'created_by': '',
        })

        self.logger.info(f"Created efficient snapshot '{snapname}' for {vm_type}/{vmid}: "
                         f"{total_alloc:.1f} GB allocated vs {total_disk_size:.1f} GB normal")

        return {
            'success': True,
            'snap_id': snap_id,
            'space_savings': {
                'normal_size_gb': total_disk_size,
                'efficient_size_gb': total_alloc,
                'savings_percent': round((1 - total_alloc / total_disk_size) * 100) if total_disk_size > 0 else 0
            }
        }

    def get_efficient_snapshots(self, cluster_id: str, vmid: int, refresh_usage: bool = False) -> list:
        """Get efficient snapshots for a VM, optionally refreshing LV usage from node."""
        db = get_db()
        snapshots = db.get_efficient_snapshots(cluster_id, vmid)

        if not refresh_usage or not snapshots:
            return snapshots

        # All snapshots for this VM are on the same node/VG
        node = snapshots[0]['node']
        vg_name = snapshots[0]['vg_name']

        # Get LV usage data via SSH
        exit_code, stdout, stderr = self._node_ssh_exec(
            node, f'lvs --noheadings --nosuffix --units g -o lv_name,lv_size,data_percent {shlex.quote(vg_name)}'
        )
        if exit_code != 0:
            return snapshots

        # Parse lvs output into lookup: lv_name -> {size, data_percent}
        lv_usage = {}
        for line in stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    lv_usage[parts[0]] = {
                        'size': float(parts[1]),
                        'data_percent': float(parts[2])
                    }
                except ValueError:
                    continue

        # Also get VG free space for auto-extend
        vg_free_gb = 0.0
        exit_code2, stdout2, _ = self._node_ssh_exec(
            node, f'vgs --noheadings --nosuffix --units g -o vg_free {shlex.quote(vg_name)}'
        )
        if exit_code2 == 0 and stdout2.strip():
            try:
                vg_free_gb = float(stdout2.strip())
            except ValueError:
                pass

        # Update each snapshot's disk usage
        for snap in snapshots:
            updated = False
            new_status = snap['status']
            for disk in snap['disks']:
                snap_lv = disk['snap_lv']
                if snap_lv in lv_usage:
                    usage = lv_usage[snap_lv]
                    disk['snap_used_percent'] = usage['data_percent']
                    disk['snap_alloc_gb'] = usage['size']
                    data_pct = usage['data_percent']

                    # Auto-extend at 90-99%
                    if 90 <= data_pct < 100:
                        extend_size = max(1.0, disk['snap_alloc_gb'] * 0.5)
                        if vg_free_gb > extend_size + 1:
                            ext_code, _, _ = self._node_ssh_exec(
                                node, f"lvextend -L +{extend_size:.0f}G /dev/{shlex.quote(vg_name)}/{shlex.quote(snap_lv)}"
                            )
                            if ext_code == 0:
                                self.logger.info(f"Auto-extended snapshot LV {snap_lv} by {extend_size:.0f}G")
                                vg_free_gb -= extend_size
                                disk['snap_alloc_gb'] += extend_size
                            new_status = 'critical'
                        else:
                            new_status = 'critical'
                    elif data_pct >= 80:
                        if new_status == 'active':
                            new_status = 'warning'
                    updated = True
                else:
                    # LV not found - snapshot was invalidated by LVM (100% full)
                    disk['snap_used_percent'] = 100.0
                    new_status = 'invalidated'
                    updated = True

            if updated:
                total_alloc = sum(d.get('snap_alloc_gb', 0) for d in snap['disks'])
                db.update_efficient_snapshot_disks(snap['id'], snap['disks'], total_alloc)
                if new_status != snap['status']:
                    snap['status'] = new_status
                    db.update_efficient_snapshot_status(snap['id'], new_status)

        # NS: Feb 2026 - Detect orphaned snapshots (disk moved to different storage)
        try:
            vm_type = snapshots[0].get('vm_type', 'qemu')
            current_lvm_disks = self._get_vm_lvm_disks(node, vmid, vm_type)
            current_disk_set = {(d['lv_name'], d['vg_name']) for d in current_lvm_disks}

            for snap in snapshots:
                if snap['status'] == 'invalidated':
                    continue
                for disk in snap['disks']:
                    if (disk['original_lv'], snap['vg_name']) not in current_disk_set:
                        snap['status'] = 'invalidated'
                        db.update_efficient_snapshot_status(
                            snap['id'], 'invalidated',
                            f"Origin LV {disk['original_lv']} no longer on storage"
                        )
                        self.logger.warning(f"Efficient snapshot '{snap['snapname']}' orphaned: "
                                            f"{disk['original_lv']} not in VG {snap['vg_name']}")
                        break
        except Exception as e:
            self.logger.warning(f"Could not validate origin LVs for VM {vmid}: {e}")

        return snapshots

    def delete_efficient_snapshot(self, node: str, vmid: int, snap_id: str) -> dict:
        """Delete an efficient snapshot: remove LVs from node, then DB record."""
        db = get_db()
        snap = db.get_efficient_snapshot(snap_id)
        if not snap:
            return {'success': False, 'error': 'Snapshot not found'}

        vg_name = snap['vg_name']
        errors = []

        for disk in snap['disks']:
            snap_lv = disk['snap_lv']
            # Check if LV still exists before trying to remove
            chk_code, chk_out, _ = self._node_ssh_exec(
                node, f"lvs /dev/{shlex.quote(vg_name)}/{shlex.quote(snap_lv)} 2>/dev/null"
            )
            if chk_code != 0:
                # LV already gone (invalidated or manually removed)
                continue

            exit_code, stdout, stderr = self._node_ssh_exec(
                node, f"lvremove -y /dev/{shlex.quote(vg_name)}/{shlex.quote(snap_lv)}"
            )
            if exit_code != 0:
                errors.append(f"{snap_lv}: {stderr or stdout}")

        if errors:
            self.logger.error(f"Errors deleting efficient snapshot LVs: {errors}")
            # Still delete DB record since partial cleanup is better than orphaned records
            db.delete_efficient_snapshot(snap_id)
            return {'success': False, 'error': f"Some LVs could not be removed: {'; '.join(errors)}"}

        db.delete_efficient_snapshot(snap_id)
        self.logger.info(f"Deleted efficient snapshot '{snap['snapname']}' for VM {vmid}")
        return {'success': True}

    def rollback_efficient_snapshot(self, node: str, vmid: int, vm_type: str, snap_id: str) -> dict:
        """Rollback VM to an efficient snapshot. VM must be stopped."""
        db = get_db()
        snap = db.get_efficient_snapshot(snap_id)
        if not snap:
            return {'success': False, 'error': 'Snapshot not found'}

        if snap['status'] == 'invalidated':
            return {'success': False, 'error': 'Snapshot invalidated (overflow)'}

        # Check VM is stopped
        try:
            host = self.current_host or self.config.host
            if vm_type == 'qemu':
                status_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/current"
            else:
                status_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/status/current"
            resp = self._create_session().get(status_url, timeout=10)
            if resp.status_code == 200:
                vm_status = resp.json().get('data', {}).get('status', '')
                if vm_status == 'running':
                    return {'success': False, 'error': 'VM must be stopped before rollback'}
        except Exception as e:
            return {'success': False, 'error': f'Cannot check VM status: {e}'}

        vg_name = snap['vg_name']
        errors = []

        for disk in snap['disks']:
            snap_lv = disk['snap_lv']
            exit_code, stdout, stderr = self._node_ssh_exec(
                node, f"lvconvert --merge /dev/{shlex.quote(vg_name)}/{shlex.quote(snap_lv)}"
            )
            if exit_code != 0:
                errors.append(f"{snap_lv}: {stderr or stdout}")

        if errors:
            db.update_efficient_snapshot_status(snap_id, 'error', '; '.join(errors))
            return {'success': False, 'error': f"Merge failed: {'; '.join(errors)}"}

        # Merge started - snapshot LV will be consumed by LVM
        db.update_efficient_snapshot_status(snap_id, 'merging')
        # Delete DB record since the LVs are being merged and will disappear
        db.delete_efficient_snapshot(snap_id)

        self.logger.info(f"Rollback started for efficient snapshot '{snap['snapname']}' on VM {vmid}")
        return {'success': True, 'message': 'Rollback started (lvconvert --merge)'}

    # ==================== REPLICATION METHODS ====================
    
    def get_replication_jobs(self, vmid: int = None) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/replication"
            response = self._api_get(url)
            
            if response.status_code == 200:
                jobs = response.json()['data']
                if vmid:
                    jobs = [j for j in jobs if j.get('guest') == vmid]
                return jobs
            return []
        except Exception as e:
            self.logger.error(f"Error getting replication jobs: {e}")
            return []
    
    def get_replication_status(self) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/replication"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json()['data']
            return []
        except Exception as e:
            self.logger.error(f"Error getting replication status: {e}")
            return []
    
    def create_replication_job(self, vmid: int, target_node: str, schedule: str = '*/15', rate: int = None, comment: str = '') -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            # Find the source node for this VM
            resources = self.get_cluster_resources()
            vm = next((r for r in resources if r.get('vmid') == vmid), None)
            if not vm:
                return {'success': False, 'error': f'VM {vmid} not found'}
            
            source_node = vm.get('node')
            vm_type = vm.get('type')
            
            # Create job ID
            job_id = f"{vmid}-0"  # Default to first replication job
            
            url = f"https://{self.host}:8006/api2/json/cluster/replication"
            
            data = {
                'id': job_id,
                'target': target_node,
                'type': 'local',
                'schedule': schedule,
            }
            
            if rate:
                data['rate'] = rate  # Rate limit in MB/s
            if comment:
                data['comment'] = comment
            
            self.logger.info(f"Creating replication job for {vmid} to {target_node}")
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'job_id': job_id}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_replication_job(self, job_id: str, keep: bool = False, force: bool = False) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/cluster/replication/{job_id}"
            
            params = {}
            if keep:
                params['keep'] = 1  # Keep replicated data
            if force:
                params['force'] = 1
            
            self.logger.info(f"Deleting replication job {job_id}")
            response = self._create_session().delete(url, params=params)
            
            if response.status_code == 200:
                return {'success': True}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_replication_now(self, job_id: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            # Extract vmid and job number from job_id (format: vmid-jobnumber)
            parts = job_id.split('-')
            vmid = parts[0]
            
            url = f"https://{self.host}:8006/api2/json/nodes/localhost/replication/{job_id}/schedule_now"
            
            self.logger.info(f"Triggering immediate replication for job {job_id}")
            response = self._create_session().post(url, timeout=15)
            
            if response.status_code == 200:
                return {'success': True}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_vnc_ticket(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            # Use the cluster host - Proxmox API will route to correct node
            host = self.current_host or self.config.host
            
            # Build URL based on VM type
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncproxy"
            else:  # lxc
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncproxy"
            
            self.logger.info(f"[VNC] Requesting ticket from {host} for {vm_type}/{vmid} on {node}")
            
            # Request websocket VNC with longer timeout
            session = self._create_session()
            response = session.post(url, data={'websocket': 1}, timeout=30)
            
            if response.status_code == 200:
                data = response.json()['data']
                ticket = data.get('ticket')
                port = data.get('port')
                self.logger.info(f"[VNC] Got ticket for {vm_type}/{vmid}, port={port}")
                
                return {
                    'success': True,
                    'ticket': ticket,
                    'port': port,
                    'host': host,
                    'node': node,
                    'vmid': vmid,
                    'vm_type': vm_type,
                    'pve_auth_cookie': self._ticket
                }
            else:
                error_msg = response.text
                self.logger.error(f"[VNC] Ticket failed ({response.status_code}): {error_msg}")
                return {'success': False, 'error': f"Proxmox error: {error_msg}"}
        
        except requests.exceptions.Timeout as e:
            self.logger.error(f"[VNC] Timeout connecting to Proxmox: {e}")
            return {'success': False, 'error': 'Proxmox connection timeout. Is the VM running?'}
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"[VNC] Connection error: {e}")
            return {'success': False, 'error': 'Cannot connect to Proxmox'}
        except Exception as e:
            self.logger.error(f"[VNC] Error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_node_shell_ticket(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/termproxy"
            
            # Request websocket terminal
            response = self._create_session().post(url, timeout=15)
            
            self.logger.info(f"Termproxy response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()['data']
                user = data.get('user') or self.config.user
                self.logger.info(f"[OK] Got shell ticket for node {node}, port={data.get('port')}, user={user}")
                return {
                    'success': True,
                    'ticket': data.get('ticket'),
                    'port': data.get('port'),
                    'user': user,
                    'host': self.config.host,
                    'node': node,
                    'pve_auth_cookie': self._ticket
                }
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Shell ticket failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Shell ticket error: {e}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def get_spice_ticket(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        
        if vm_type != 'qemu':
            return {'success': False, 'error': 'SPICE only available for QEMU VMs'}
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/spiceproxy"
            response = self._create_session().post(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()['data']
                self.logger.info(f"[OK] Got SPICE ticket for {vmid}")
                return {'success': True, 'data': data}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_vm_config(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            response = self._api_get(url)
            
            if response.status_code == 200:
                config = response.json()['data']
                
                # Also get current status for some dynamic info
                if vm_type == 'qemu':
                    status_url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/current"
                else:
                    status_url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/status/current"
                
                status_response = self._create_session().get(status_url, timeout=15)
                status = {}
                if status_response.status_code == 200:
                    status = status_response.json()['data']
                
                # Parse config into structured format
                parsed = self._parse_vm_config(config, vm_type)
                parsed['raw'] = config
                parsed['status'] = status
                parsed['vmid'] = vmid
                parsed['node'] = node
                parsed['type'] = vm_type
                
                # MK: Add lock info - important for UI to show locked state
                lock_reason = config.get('lock')
                if lock_reason:
                    parsed['lock'] = {
                        'locked': True,
                        'reason': lock_reason,
                        'description': self.LOCK_DESCRIPTIONS.get(lock_reason, f'Locked: {lock_reason}'),
                        'unlock_command': f"qm unlock {vmid}" if vm_type == 'qemu' else f"pct unlock {vmid}"
                    }
                else:
                    parsed['lock'] = {'locked': False}
                
                return {'success': True, 'config': parsed}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Get VM config error: {e}")
            return {'success': False, 'error': str(e)}
    
    def unlock_vm(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        """remove lock from VM config - use carefully during stuck operations"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            
            # First get current config to see lock reason
            if vm_type == 'qemu':
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            config_response = self._api_get(config_url)
            if config_response.status_code != 200:
                return {'success': False, 'error': 'Could not get VM config'}
            
            config = config_response.json().get('data', {})
            lock_reason = config.get('lock')
            
            if not lock_reason:
                return {'success': True, 'message': 'VM is not locked', 'was_locked': False}
            
            self.logger.info(f"Unlocking {vm_type}/{vmid} on {node} (lock reason: {lock_reason})")
            
            # Remove the lock by setting delete=lock
            response = self._api_put(config_url, data={'delete': 'lock'})
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Unlocked {vm_type}/{vmid} (was: {lock_reason})")
                return {
                    'success': True, 
                    'message': f'VM unlocked successfully',
                    'was_locked': True,
                    'lock_reason': lock_reason
                }
            else:
                error = response.text
                self.logger.error(f"[ERROR] Failed to unlock {vm_type}/{vmid}: {error}")
                return {'success': False, 'error': error}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Unlock VM error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_vm_lock_status(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        """Get lock status of a VM/CT"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            
            if vm_type == 'qemu':
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                config_url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            response = self._api_get(config_url)
            
            if response.status_code == 200:
                config = response.json().get('data', {})
                lock_reason = config.get('lock')
                
                return {
                    'success': True,
                    'locked': bool(lock_reason),
                    'lock_reason': lock_reason,
                    'lock_description': self.LOCK_DESCRIPTIONS.get(lock_reason, f'Locked: {lock_reason}') if lock_reason else None
                }
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_vm_rrd(self, node: str, vmid: int, vm_type: str, timeframe: str = 'day') -> Dict[str, Any]:
        """Get RRD metrics data for a VM or container
        
        Proxmox stores historical data in RRD format.
        Timeframes: hour, day, week, month, year
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            
            if vm_type == 'qemu':
                url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/rrddata"
            else:
                url = f"https://{host}:8006/api2/json/nodes/{node}/lxc/{vmid}/rrddata"
            
            response = self._create_session().get(url, params={'timeframe': timeframe})
            
            if response.status_code == 200:
                rrd_data = response.json().get('data', [])
                
                # Process and format the data for charts
                formatted_data = {
                    'timeframe': timeframe,
                    'vmid': vmid,
                    'node': node,
                    'type': vm_type,
                    'metrics': {
                        'cpu': [],
                        'memory': [],
                        'disk_read': [],
                        'disk_write': [],
                        'net_in': [],
                        'net_out': []
                    },
                    'timestamps': []
                }

                # Check for pressure stall data (PSI)
                pressure_keys = [
                    'pressurecpusome', 'pressurecpufull',
                    'pressurememorysome', 'pressurememoryfull',
                    'pressureiosome', 'pressureiofull'
                ]
                active_pressure_keys = []

                # Check first valid point to determine available metrics
                if rrd_data:
                    first_point = next((p for p in rrd_data if p), None)
                    if first_point:
                        for k in pressure_keys:
                            if k in first_point:
                                active_pressure_keys.append(k)
                                formatted_data['metrics'][k] = []

                for point in rrd_data:
                    if not point:
                        continue
                    
                    timestamp = point.get('time', 0)
                    formatted_data['timestamps'].append(timestamp)
                    
                    # CPU usage (0-1 -> 0-100%)
                    cpu = point.get('cpu', 0)
                    formatted_data['metrics']['cpu'].append(round((cpu or 0) * 100, 2))
                    
                    # Memory usage (bytes)
                    mem = point.get('mem', 0)
                    maxmem = point.get('maxmem', 1)
                    mem_percent = ((mem or 0) / (maxmem or 1)) * 100
                    formatted_data['metrics']['memory'].append(round(mem_percent, 2))
                    
                    # Disk I/O (bytes/s)
                    formatted_data['metrics']['disk_read'].append(point.get('diskread', 0) or 0)
                    formatted_data['metrics']['disk_write'].append(point.get('diskwrite', 0) or 0)
                    
                    # Network I/O (bytes/s)
                    formatted_data['metrics']['net_in'].append(point.get('netin', 0) or 0)
                    formatted_data['metrics']['net_out'].append(point.get('netout', 0) or 0)

                    # Pressure Stall (PSI)
                    for k in active_pressure_keys:
                        formatted_data['metrics'][k].append(point.get(k, 0) or 0)
                
                return {'success': True, 'data': formatted_data}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Get VM RRD error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_vm_config(self, config: Dict, vm_type: str) -> Dict:
        
        parsed = {
            'general': {},
            'hardware': {},
            'disks': [],
            'networks': [],
            'options': {},
            'unused_disks': []  # MK: Track unused/detached disks
        }
        
        if vm_type == 'qemu':
            # General
            parsed['general'] = {
                'name': config.get('name', ''),
                'description': config.get('description', ''),
                'vmgenid': config.get('vmgenid', ''),
                'tags': config.get('tags', ''),
            }
            
            # Hardware
            parsed['hardware'] = {
                'cores': config.get('cores', 1),
                'sockets': config.get('sockets', 1),
                'cpu': config.get('cpu', 'host'),
                'memory': config.get('memory', 512),
                'balloon': config.get('balloon', 0),
                'numa': config.get('numa', 0),
                'vga': config.get('vga', 'std'),
                'machine': config.get('machine', ''),
                'bios': config.get('bios', 'seabios'),
                'scsihw': config.get('scsihw', 'virtio-scsi-pci'),
            }
            
            # Options
            parsed['options'] = {
                'onboot': config.get('onboot', 0),
                'boot': config.get('boot', ''),
                'bootdisk': config.get('bootdisk', ''),
                'ostype': config.get('ostype', 'other'),
                'agent': config.get('agent', '0'),
                'protection': config.get('protection', 0),
                'tablet': config.get('tablet', 1),
                'hotplug': config.get('hotplug', ''),
                'acpi': config.get('acpi', 1),
                'kvm': config.get('kvm', 1),
                'smbios1': config.get('smbios1', ''),
            }
            
            # Parse disks and networks from config keys
            for key, value in config.items():
                # Disks: scsi0, virtio0, ide0, sata0, etc.
                if any(key.startswith(prefix) for prefix in ['scsi', 'virtio', 'ide', 'sata', 'efidisk', 'tpmstate']):
                    if isinstance(value, str) and ':' in value:
                        parsed['disks'].append({
                            'id': key,
                            'value': value,
                            **self._parse_disk_string(value)
                        })
                
                # MK: Unused disks - these are detached but not deleted
                if key.startswith('unused'):
                    if isinstance(value, str):
                        # Parse unused disk: "local-lvm:vm-100-disk-1" or similar
                        parts = value.split(':')
                        storage = parts[0] if len(parts) > 0 else ''
                        volume = parts[1] if len(parts) > 1 else value
                        parsed['unused_disks'].append({
                            'id': key,
                            'value': value,
                            'storage': storage,
                            'volume': volume,
                        })
                
                # Networks: net0, net1, etc.
                if key.startswith('net'):
                    parsed['networks'].append({
                        'id': key,
                        'value': value,
                        **self._parse_network_string(value, 'qemu')
                    })
                
                # CD/DVD
                if key in ['cdrom', 'ide2'] and 'media=cdrom' in str(value):
                    parsed['hardware']['cdrom'] = value
        
        else:  # LXC
            # General
            parsed['general'] = {
                'hostname': config.get('hostname', ''),
                'description': config.get('description', ''),
                'tags': config.get('tags', ''),
                'ostype': config.get('ostype', ''),
                'arch': config.get('arch', 'amd64'),
            }
            
            # Hardware/Resources
            parsed['hardware'] = {
                'cores': config.get('cores', 1),
                'cpulimit': config.get('cpulimit', 0),
                'cpuunits': config.get('cpuunits', 1024),
                'memory': config.get('memory', 512),
                'swap': config.get('swap', 512),
            }
            
            # Options
            parsed['options'] = {
                'onboot': config.get('onboot', 0),
                'protection': config.get('protection', 0),
                'unprivileged': config.get('unprivileged', 0),
                'features': config.get('features', ''),
                'startup': config.get('startup', ''),
                'nameserver': config.get('nameserver', ''),
                'searchdomain': config.get('searchdomain', ''),
            }
            
            # Parse storage and networks
            for key, value in config.items():
                # Storage: rootfs, mp0, mp1, etc.
                if key == 'rootfs' or key.startswith('mp'):
                    parsed['disks'].append({
                        'id': key,
                        'value': value,
                        **self._parse_lxc_storage_string(value)
                    })
                
                # MK: Unused disks for LXC too
                if key.startswith('unused'):
                    if isinstance(value, str):
                        parts = value.split(':')
                        storage = parts[0] if len(parts) > 0 else ''
                        volume = parts[1] if len(parts) > 1 else value
                        parsed['unused_disks'].append({
                            'id': key,
                            'value': value,
                            'storage': storage,
                            'volume': volume,
                        })
                
                # Networks: net0, net1, etc.
                if key.startswith('net'):
                    parsed['networks'].append({
                        'id': key,
                        'value': value,
                        **self._parse_network_string(value, 'lxc')
                    })
        
        return parsed
    
    def _parse_disk_string(self, disk_str: str) -> Dict:
        """Parse QEMU disk string like 'local-lvm:vm-100-disk-0,size=32G'"""
        result = {'storage': '', 'size': '', 'format': '', 'cache': '', 'iothread': 0, 'ssd': 0}
        parts = disk_str.split(',')
        
        if parts:
            # First part is storage:volume
            if ':' in parts[0]:
                storage_parts = parts[0].split(':')
                result['storage'] = storage_parts[0]
                result['volume'] = storage_parts[1] if len(storage_parts) > 1 else ''
        
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                if key == 'size':
                    result['size'] = value
                elif key == 'cache':
                    result['cache'] = value
                elif key == 'format':
                    result['format'] = value
                elif key == 'iothread':
                    result['iothread'] = int(value)
                elif key == 'ssd':
                    result['ssd'] = int(value)
        
        return result
    
    def _parse_lxc_storage_string(self, storage_str: str) -> Dict:
        """Parse LXC storage string like 'local-lvm:vm-100-disk-0,size=8G'"""
        result = {'storage': '', 'size': '', 'mountpoint': ''}
        parts = storage_str.split(',')
        
        if parts:
            if ':' in parts[0]:
                storage_parts = parts[0].split(':')
                result['storage'] = storage_parts[0]
                result['volume'] = storage_parts[1] if len(storage_parts) > 1 else ''
        
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                if key == 'size':
                    result['size'] = value
                elif key == 'mp':
                    result['mountpoint'] = value
        
        return result
    
    def _parse_network_string(self, net_str: str, vm_type: str) -> Dict:
        """Parse Proxmox network config string into a dict
        
        MK: Format varies between QEMU and LXC
        QEMU: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,link_down=1,queues=4
        LXC: name=eth0,bridge=vmbr0,ip=dhcp,hwaddr=AA:BB:CC:DD:EE:FF
        """
        result = {
            'bridge': '',
            'firewall': 0,
            'tag': '',
            'rate': '',
            'mtu': '',
            'queues': '',  # LW: multiqueue support
            'link_down': False,  # NS: track network disconnect state
        }
        
        if vm_type == 'qemu':
            result.update({'model': 'virtio', 'macaddr': ''})
        else:  # lxc
            result.update({'name': '', 'hwaddr': '', 'ip': '', 'gw': '', 'ip6': '', 'gw6': ''})
        
        parts = net_str.split(',')
        
        for i, part in enumerate(parts):
            if '=' in part:
                key, value = part.split('=', 1)
                key_lower = key.lower()
                
                # First part for QEMU: model=MAC (e.g., e1000=AA:BB:CC:DD:EE:FF)
                if i == 0 and vm_type == 'qemu' and ':' in value:
                    # This is model=MAC format
                    result['model'] = key
                    result['macaddr'] = value
                elif key == 'bridge':
                    result['bridge'] = value
                elif key == 'firewall':
                    result['firewall'] = int(value)
                elif key == 'tag':
                    result['tag'] = value
                elif key == 'rate':
                    result['rate'] = value
                elif key == 'mtu':
                    result['mtu'] = value
                elif key == 'queues':
                    result['queues'] = value
                elif key == 'model':
                    result['model'] = value
                elif key == 'macaddr' or key == 'hwaddr':
                    result['macaddr' if vm_type == 'qemu' else 'hwaddr'] = value
                elif key == 'name':
                    result['name'] = value
                elif key == 'ip':
                    result['ip'] = value
                elif key == 'gw':
                    result['gw'] = value
                elif key == 'ip6':
                    result['ip6'] = value
                elif key == 'gw6':
                    result['gw6'] = value
                elif key == 'link_down':
                    # LW: link_down=1 means cable is "unplugged"
                    result['link_down'] = value == '1'
        
        return result
    
    def update_vm_config(self, node: str, vmid: int, vm_type: str, config_updates: Dict) -> Dict[str, Any]:
        """Update VM configuration with boot order validation.
        
        NS: Feb 2026 - Added automatic boot order sanitization to prevent
        'device does not exist' errors when updating config.
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            # NS: If boot order is being updated, validate it against current config
            if 'boot' in config_updates:
                boot_val = config_updates.get('boot', '')
                if boot_val and 'order=' in boot_val:
                    # Get current VM config to validate boot devices
                    current_config = self.get_vm_config(node, vmid, vm_type)
                    if current_config.get('success'):
                        config = current_config.get('config', {})
                        # Parse and validate boot order
                        order_str = boot_val.split('order=')[1].split(';')[0] if 'order=' in boot_val else ''
                        if order_str:
                            devices = [d.strip() for d in order_str.split(';') if d.strip()]
                            valid_devices = []
                            for dev in devices:
                                # Check if device exists in config
                                if dev in config or dev == 'net0':  # net0 is always valid
                                    valid_devices.append(dev)
                                else:
                                    self.logger.warning(f"Boot order device '{dev}' not found in VM config, removing")
                            
                            if valid_devices:
                                config_updates['boot'] = 'order=' + ';'.join(valid_devices)
                            else:
                                # No valid boot devices - remove boot order from update
                                del config_updates['boot']
                                self.logger.warning(f"No valid boot devices found, skipping boot order update")
            
            self.logger.info(f"Updating {vm_type}/{vmid} config: {config_updates}")
            
            response = self._api_put(url, data=config_updates)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Config updated for {vm_type}/{vmid}")
                return {'success': True, 'message': 'Configuration updated'}
            else:
                error_msg = response.text
                self.logger.error(f"[ERROR] Config update failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Update config error: {e}")
            return {'success': False, 'error': str(e)}
    
    def sanitize_boot_order(self, node: str, vmid: int, vm_type: str) -> Dict[str, Any]:
        """Sanitize boot order by removing non-existent devices.
        
        NS: Feb 2026 - Fixes 'invalid bootorder: device does not exist' errors
        by removing devices from boot order that no longer exist in the VM config.
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            # Get current config
            config_result = self.get_vm_config(node, vmid, vm_type)
            if not config_result.get('success'):
                return {'success': False, 'error': 'Could not get VM config'}
            
            config = config_result.get('config', {})
            boot_val = config.get('boot', '')
            
            if not boot_val or 'order=' not in boot_val:
                return {'success': True, 'message': 'No boot order to sanitize', 'changed': False}
            
            # Parse boot order
            order_part = boot_val.split('order=')[1].split(';')[0] if 'order=' in boot_val else ''
            if not order_part:
                return {'success': True, 'message': 'Empty boot order', 'changed': False}
            
            devices = [d.strip() for d in boot_val.split('order=')[1].split(';') if d.strip()]
            valid_devices = []
            removed_devices = []
            
            for dev in devices:
                # Check if device exists in config (net0 is always valid for QEMU)
                if dev in config or (dev == 'net0' and vm_type == 'qemu'):
                    valid_devices.append(dev)
                else:
                    removed_devices.append(dev)
                    self.logger.info(f"Boot order: removing non-existent device '{dev}' from VM {vmid}")
            
            if not removed_devices:
                return {'success': True, 'message': 'Boot order is valid', 'changed': False}
            
            # Update boot order
            if valid_devices:
                new_boot = 'order=' + ';'.join(valid_devices)
            else:
                # No valid devices - default to net0 for QEMU
                new_boot = 'order=net0' if vm_type == 'qemu' else ''
            
            # Apply update
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            response = self._api_put(url, data={'boot': new_boot})
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Sanitized boot order for {vm_type}/{vmid}: removed {removed_devices}")
                return {
                    'success': True, 
                    'message': f'Removed invalid devices: {", ".join(removed_devices)}',
                    'changed': True,
                    'removed': removed_devices,
                    'new_boot_order': new_boot
                }
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Sanitize boot order error: {e}")
            return {'success': False, 'error': str(e)}

    def resize_vm_disk(self, node: str, vmid: int, vm_type: str, disk: str, size: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/resize"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/resize"
            
            data = {'disk': disk, 'size': size}
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Disk {disk} resized to {size}")
                return {'success': True, 'message': f'Disk resized to {size}'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_storage_list(self, node: str) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/storage"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json()['data']
            return []
        except:
            return []
    
    def get_network_list(self, node: str) -> List[Dict]:
        """Get available networks/bridges for a node, including SDN VNets
        
        NS: Feb 2026 - Added SDN VNet support (GitHub Issue #38)
        SDN VNets are cluster-wide virtual networks that appear as bridges
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            result = []
            found_bridges = set()
            
            # 1. Get local bridges from node
            url = f"https://{host}:8006/api2/json/nodes/{node}/network"
            response = self._api_get(url)
            
            if response.status_code == 200:
                networks = response.json()['data']
                # Filter to just bridges and OVS bridges
                for n in networks:
                    if n.get('type') in ['bridge', 'OVSBridge', 'OVSIntPort']:
                        n['source'] = 'local'
                        result.append(n)
                        if n.get('iface'):
                            found_bridges.add(n['iface'])
            
            # 2. Get SDN VNets (cluster-wide)
            # NS: Feb 2026 - Improved SDN support for GitHub Issue #38
            try:
                sdn_url = f"https://{host}:8006/api2/json/cluster/sdn/vnets"
                sdn_response = self._api_get(sdn_url)
                
                if sdn_response.status_code == 200:
                    vnets = sdn_response.json().get('data', [])
                    logging.info(f"Found {len(vnets)} SDN VNets")
                    for vnet in vnets:
                        vnet_name = vnet.get('vnet', '')
                        if vnet_name and vnet_name not in found_bridges:
                            result.append({
                                'iface': vnet_name,
                                'type': 'sdn_vnet',
                                'source': 'sdn',
                                'zone': vnet.get('zone', ''),
                                'alias': vnet.get('alias', ''),
                                'tag': vnet.get('tag'),
                                'vlanaware': vnet.get('vlanaware'),
                                'comments': f"SDN: {vnet.get('zone', '')}",
                                'active': True,
                            })
                            found_bridges.add(vnet_name)
                elif sdn_response.status_code == 501:
                    logging.debug("SDN not enabled on this cluster")
                else:
                    logging.warning(f"SDN VNets API returned {sdn_response.status_code}")
            except Exception as e:
                logging.debug(f"SDN VNets not available: {e}")
            
            # 3. Get SDN Zones and update VNet info
            try:
                zones_url = f"https://{host}:8006/api2/json/cluster/sdn/zones"
                zones_response = self._api_get(zones_url)
                
                if zones_response.status_code == 200:
                    zones = zones_response.json().get('data', [])
                    zone_map = {z.get('zone', ''): z for z in zones}
                    
                    for item in result:
                        if item.get('source') == 'sdn' and item.get('zone') in zone_map:
                            zone_info = zone_map[item['zone']]
                            item['zone_type'] = zone_info.get('type', '')
            except Exception as e:
                logging.debug(f"SDN Zones not available: {e}")
            
            # 4. Discover networks from running VMs (catches SDN VNets not in API)
            try:
                vms_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu"
                vms_response = self._api_get(vms_url)
                
                if vms_response.status_code == 200:
                    vms = vms_response.json().get('data', [])
                    
                    for vm in vms[:15]:  # Check first 15 VMs
                        vmid = vm.get('vmid')
                        if vmid:
                            config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                            config_response = self._api_get(config_url)
                            
                            if config_response.status_code == 200:
                                config = config_response.json().get('data', {})
                                for key, value in config.items():
                                    if key.startswith('net') and isinstance(value, str):
                                        for part in value.split(','):
                                            if part.startswith('bridge='):
                                                bridge_name = part.split('=')[1]
                                                if bridge_name and bridge_name not in found_bridges:
                                                    logging.info(f"Discovered network '{bridge_name}' from VM {vmid}")
                                                    result.append({
                                                        'iface': bridge_name,
                                                        'type': 'sdn_vnet',
                                                        'source': 'sdn',
                                                        'zone': '',
                                                        'comments': 'SDN (discovered)',
                                                        'active': True,
                                                    })
                                                    found_bridges.add(bridge_name)
                                                break
            except Exception as e:
                logging.debug(f"Could not scan VMs for networks: {e}")
            
            return result
        except Exception as e:
            logging.error(f"Error getting network list: {e}")
            return []

    def get_iso_list(self, node: str, storage: str = None) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            isos = []
            # Get all storage if not specified
            storages = [storage] if storage else [s['storage'] for s in self.get_storage_list(node) if 'iso' in s.get('content', '')]
            
            for stor in storages:
                url = f"https://{host}:8006/api2/json/nodes/{node}/storage/{stor}/content"
                response = self._create_session().get(url, params={'content': 'iso'})
                
                if response.status_code == 200:
                    content = response.json()['data']
                    for item in content:
                        item['storage'] = stor
                        isos.append(item)
            
            return isos
        except Exception as e:
            self.logger.error(f"Error getting ISO list: {e}")
            return []
    
    # MK: Resource Pools - Jan 2026
    def get_pools(self) -> List[Dict]:
        """Get all resource pools from Proxmox"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/pools"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting pools: {e}")
            return []
    
    def get_pool_members(self, pool_id: str) -> Dict:
        """Get pool details including members"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/pools/{pool_id}"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting pool members: {e}")
            return {}
    
    def get_vm_pool(self, vmid: int, vm_type: str = 'qemu') -> str:
        """Get the pool a VM belongs to (if any)"""
        pools = self.get_pools()
        for pool in pools:
            pool_data = self.get_pool_members(pool['poolid'])
            members = pool_data.get('members', [])
            for member in members:
                if member.get('vmid') == vmid and member.get('type') == vm_type:
                    return pool['poolid']
        return None
    
    def add_disk(self, node: str, vmid: int, vm_type: str, disk_config: Dict) -> Dict[str, Any]:
        """Add a new disk to VM or container
        
        LW: This was a pain to get right - Proxmox disk strings are weird
        MK: Jan 2026 - Added bus type detection for iothread/ssd support
        MK: Fixed to use PUT instead of POST for config updates
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            storage = disk_config.get('storage', 'local-lvm')
            size = str(disk_config.get('size', '32')).replace('G', '').replace('g', '')
            disk_id = disk_config.get('disk_id', 'scsi1')
            
            # MK: Determine bus type from disk_id (e.g., "scsi0" -> "scsi")
            bus_type = ''.join(c for c in disk_id if c.isalpha())
            # LW: iothread only works with virtio-scsi controller
            supports_iothread = bus_type in ['scsi', 'virtio']
            # MK: ssd emulation supported for scsi, virtio, sata (NOT ide - tried it, breaks)
            supports_ssd = bus_type in ['scsi', 'virtio', 'sata']
            
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                
                # Build disk string - format is storage:size (size in GB without unit)
                disk_str = f"{storage}:{size}"
                
                # Add optional parameters (only if supported by bus type)
                if disk_config.get('cache'):
                    disk_str += f",cache={disk_config['cache']}"
                # MK: Only add iothread for scsi/virtio
                if disk_config.get('iothread') and supports_iothread:
                    disk_str += ",iothread=1"
                # MK: Only add ssd for scsi/virtio/sata (not ide)
                if disk_config.get('ssd') and supports_ssd:
                    disk_str += ",ssd=1"
                if disk_config.get('discard'):
                    disk_str += ",discard=on"
                if disk_config.get('backup') == False:
                    disk_str += ",backup=0"
                
                data = {disk_id: disk_str}
                
            else:  # LXC
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
                
                # For LXC mountpoints
                mp_str = f"{storage}:{size}"
                if disk_config.get('mountpoint'):
                    mp_str += f",mp={disk_config['mountpoint']}"
                if disk_config.get('backup') == False:
                    mp_str += ",backup=0"
                
                data = {disk_id: mp_str}
            
            # MK: Use PUT for config updates (not POST)
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Added disk {disk_id} to {vm_type}/{vmid}")
                return {'success': True, 'message': f'Disk {disk_id} added'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def remove_disk(self, node: str, vmid: int, vm_type: str, disk_id: str, delete_data: bool = False) -> Dict[str, Any]:
        """
        Remove disk from VM.
        If delete_data=False: Only detach (disk becomes unused)
        If delete_data=True: Detach AND delete the volume physically
        
        MK: Fixed - after detach, disk becomes 'unused0' etc., so we need to delete that
        NS: Feb 2026 - Now auto-cleans boot order BEFORE removing disk to prevent errors
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            # NS: FIRST get current config and clean boot order if needed
            config_result = self.get_vm_config(node, vmid, vm_type)
            volume_path = None
            
            if config_result.get('success'):
                parsed_config = config_result.get('config', {})
                raw_config = parsed_config.get('raw', {})
                
                # Check if disk is in boot order and remove it BEFORE deleting the disk
                old_boot = raw_config.get('boot', '')
                if old_boot and disk_id in old_boot and 'order=' in old_boot:
                    try:
                        # Parse boot order (format: order=scsi0;ide2;net0)
                        order_part = old_boot.split('order=')[1]
                        # Handle potential trailing options after boot order
                        if ' ' in order_part:
                            order_part = order_part.split(' ')[0]
                        parts = [p.strip() for p in order_part.split(';') if p.strip()]
                        new_parts = [p for p in parts if p != disk_id]
                        
                        if new_parts != parts:  # Boot order changed
                            if new_parts:
                                new_boot = 'order=' + ';'.join(new_parts)
                            else:
                                new_boot = 'order=net0' if vm_type == 'qemu' else ''
                            
                            # Update boot order BEFORE removing disk
                            if vm_type == 'qemu':
                                boot_url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                            else:
                                boot_url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
                            
                            boot_response = self._api_put(boot_url, data={'boot': new_boot})
                            if boot_response.status_code == 200:
                                self.logger.info(f"[DISK] Updated boot order before removing {disk_id}: {new_boot}")
                            else:
                                self.logger.warning(f"[DISK] Failed to update boot order: {boot_response.text}")
                    except Exception as e:
                        self.logger.warning(f"[DISK] Error updating boot order: {e}")
                
                # Get volume path for delete_data
                if delete_data:
                    disk_config = raw_config.get(disk_id, '')
                    self.logger.info(f"[DEBUG] delete_data=True, disk_id={disk_id}, disk_config={disk_config}")
                    if disk_config and ':' in str(disk_config):
                        volume_path = disk_config.split(',')[0]
                        self.logger.info(f"[DEBUG] volume_path={volume_path}")
            
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            # Now detach the disk from VM config
            data = {'delete': disk_id}
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Detached disk {disk_id} from {vm_type}/{vmid}")
                
                # MK: If delete_data is True, find the unused slot and delete it
                if delete_data and volume_path:
                    try:
                        import time
                        time.sleep(2)  # NS: Feb 2026 - Wait for Proxmox to update config (was 0.8s, increased for reliability)
                        
                        # Get updated config to find the unused slot with our volume
                        new_config = self.get_vm_config(node, vmid, vm_type)
                        if new_config.get('success'):
                            # MK: Structure is new_config['config']['raw']
                            parsed_config = new_config.get('config', {})
                            raw_config = parsed_config.get('raw', {})
                            
                            # Find the unused slot containing our volume
                            unused_slot = None
                            for key, value in raw_config.items():
                                if key.startswith('unused') and volume_path in str(value):
                                    unused_slot = key
                                    self.logger.info(f"[DEBUG] Found {volume_path} in {key}={value}")
                                    break
                            
                            if unused_slot:
                                # Delete the unused slot - this removes the volume
                                delete_data_req = {'delete': unused_slot}
                                delete_response = self._api_put(url, data=delete_data_req)
                                if delete_response.status_code == 200:
                                    self.logger.info(f"[OK] Deleted volume via {unused_slot}")
                                    return {'success': True, 'message': f'Disk {disk_id} removed and deleted'}
                                else:
                                    self.logger.warning(f"[WARN] Failed to delete {unused_slot}: {delete_response.text}")
                            else:
                                self.logger.warning(f"[WARN] Could not find {volume_path} in unused slots. Raw config keys: {list(raw_config.keys())}")
                                # Volume not found in unused - try direct storage API delete
                                storage_name = volume_path.split(':')[0] if ':' in volume_path else None
                                if storage_name:
                                    import urllib.parse
                                    encoded_volid = urllib.parse.quote(volume_path, safe='')
                                    delete_url = f"https://{self.host}:8006/api2/json/nodes/{node}/storage/{storage_name}/content/{encoded_volid}"
                                    delete_response = self._api_delete(delete_url)
                                    if delete_response.status_code == 200:
                                        self.logger.info(f"[OK] Deleted volume {volume_path} via storage API")
                                        return {'success': True, 'message': f'Disk {disk_id} removed and deleted'}
                                    else:
                                        self.logger.warning(f"[WARN] Storage API delete failed: {delete_response.text}")
                        
                        return {'success': True, 'message': f'Disk {disk_id} detached (volume may still exist)'}
                    except Exception as del_err:
                        self.logger.warning(f"[WARN] Could not delete volume: {del_err}")
                        return {'success': True, 'message': f'Disk {disk_id} detached (volume deletion failed)'}
                elif delete_data and not volume_path:
                    self.logger.warning(f"[WARN] delete_data=True but volume_path is None - could not extract volume path from config")
                
                return {'success': True, 'message': f'Disk {disk_id} detached'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def move_disk(self, node: str, vmid: int, vm_type: str, disk_id: str, target_storage: str, delete_original: bool = True) -> Dict[str, Any]:

        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}

        # NS: Feb 2026 - Block move if disk has active efficient snapshot
        try:
            db = get_db()
            existing = db.get_efficient_snapshots(self.id, vmid)
            for snap in existing:
                if snap['status'] in ('invalidated', 'error'):
                    continue
                for d in snap['disks']:
                    if d['disk_key'] == disk_id:
                        return {'success': False, 'error': f"Disk has active efficient snapshot '{snap['snapname']}', delete it first"}
        except Exception as e:
            self.logger.warning(f"Could not check efficient snapshots for VM {vmid}: {e}")

        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/move_disk"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/move_volume"
            
            data = {
                'disk': disk_id,
                'storage': target_storage,
                'delete': 1 if delete_original else 0
            }
            
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                task_id = response.json().get('data')
                self.logger.info(f"[OK] Moving disk {disk_id} to {target_storage} (Task: {task_id})")
                return {'success': True, 'message': f'Disk move started', 'task': task_id}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def set_cdrom(self, node: str, vmid: int, iso_path: str = None, drive: str = 'ide2') -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            
            if iso_path:
                # Mount ISO
                data = {drive: f"{iso_path},media=cdrom"}
            else:
                # Eject - set to none
                data = {drive: "none,media=cdrom"}
            
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                action = "mounted" if iso_path else "ejected"
                self.logger.info(f"[OK] CD-ROM {action} for VM {vmid}")
                return {'success': True, 'message': f'CD-ROM {action}'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def add_network(self, node: str, vmid: int, vm_type: str, net_config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            net_id = net_config.get('net_id', 'net1')
            
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                
                # Build network string: model=XX:XX:XX:XX:XX:XX,bridge=vmbr0,...
                model = net_config.get('model', 'virtio')
                parts = [model]
                
                if net_config.get('macaddr'):
                    parts[0] = f"{model}={net_config['macaddr']}"
                
                if net_config.get('bridge'):
                    parts.append(f"bridge={net_config['bridge']}")
                if net_config.get('tag'):
                    parts.append(f"tag={net_config['tag']}")
                if net_config.get('firewall'):
                    parts.append("firewall=1")
                if net_config.get('rate'):
                    parts.append(f"rate={net_config['rate']}")
                if net_config.get('queues'):
                    parts.append(f"queues={net_config['queues']}")
                if net_config.get('mtu'):
                    parts.append(f"mtu={net_config['mtu']}")
                
                net_str = ','.join(parts)
                
            else:  # LXC
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
                
                parts = []
                if net_config.get('name'):
                    parts.append(f"name={net_config['name']}")
                if net_config.get('bridge'):
                    parts.append(f"bridge={net_config['bridge']}")
                if net_config.get('hwaddr'):
                    parts.append(f"hwaddr={net_config['hwaddr']}")
                if net_config.get('ip'):
                    parts.append(f"ip={net_config['ip']}")
                if net_config.get('gw'):
                    parts.append(f"gw={net_config['gw']}")
                if net_config.get('ip6'):
                    parts.append(f"ip6={net_config['ip6']}")
                if net_config.get('gw6'):
                    parts.append(f"gw6={net_config['gw6']}")
                if net_config.get('tag'):
                    parts.append(f"tag={net_config['tag']}")
                if net_config.get('firewall'):
                    parts.append("firewall=1")
                if net_config.get('rate'):
                    parts.append(f"rate={net_config['rate']}")
                if net_config.get('mtu'):
                    parts.append(f"mtu={net_config['mtu']}")
                
                net_str = ','.join(parts)
            
            data = {net_id: net_str}
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Added network {net_id} to {vm_type}/{vmid}")
                return {'success': True, 'message': f'Network {net_id} added'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def update_network(self, node: str, vmid: int, vm_type: str, net_id: str, net_config: Dict) -> Dict[str, Any]:
        """Update network configuration
        
        NS: Supports all Proxmox network options including:
        - link_down (disconnect simulation)
        - queues (multiqueue for VirtIO)
        - rate limit, MTU, VLAN tag
        """
        # Same as add but uses PUT
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
                
                model = net_config.get('model', 'virtio')
                parts = [model]
                
                if net_config.get('macaddr'):
                    parts[0] = f"{model}={net_config['macaddr']}"
                
                if net_config.get('bridge'):
                    parts.append(f"bridge={net_config['bridge']}")
                if net_config.get('tag'):
                    parts.append(f"tag={net_config['tag']}")
                if net_config.get('firewall'):
                    parts.append("firewall=1")
                if net_config.get('rate'):
                    parts.append(f"rate={net_config['rate']}")
                if net_config.get('queues'):
                    parts.append(f"queues={net_config['queues']}")
                if net_config.get('mtu'):
                    parts.append(f"mtu={net_config['mtu']}")
                # LW: link_down=1 simulates unplugged cable
                if net_config.get('link_down'):
                    parts.append("link_down=1")
                
                net_str = ','.join(parts)
                
            else:  # LXC
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
                
                parts = []
                if net_config.get('name'):
                    parts.append(f"name={net_config['name']}")
                if net_config.get('bridge'):
                    parts.append(f"bridge={net_config['bridge']}")
                if net_config.get('hwaddr'):
                    parts.append(f"hwaddr={net_config['hwaddr']}")
                if net_config.get('ip'):
                    parts.append(f"ip={net_config['ip']}")
                if net_config.get('gw'):
                    parts.append(f"gw={net_config['gw']}")
                if net_config.get('ip6'):
                    parts.append(f"ip6={net_config['ip6']}")
                if net_config.get('gw6'):
                    parts.append(f"gw6={net_config['gw6']}")
                if net_config.get('tag'):
                    parts.append(f"tag={net_config['tag']}")
                if net_config.get('firewall'):
                    parts.append("firewall=1")
                if net_config.get('rate'):
                    parts.append(f"rate={net_config['rate']}")
                if net_config.get('mtu'):
                    parts.append(f"mtu={net_config['mtu']}")
                
                net_str = ','.join(parts)
            
            data = {net_id: net_str}
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Updated network {net_id} on {vm_type}/{vmid}")
                return {'success': True, 'message': f'Network {net_id} updated'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def remove_network(self, node: str, vmid: int, vm_type: str, net_id: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            if vm_type == 'qemu':
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            else:
                url = f"https://{self.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/config"
            
            data = {'delete': net_id}
            response = self._api_put(url, data=data)
            
            if response.status_code == 200:
                self.logger.info(f"[OK] Removed network {net_id} from {vm_type}/{vmid}")
                return {'success': True, 'message': f'Network {net_id} removed'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def toggle_network_link(self, node: str, vmid: int, net_id: str, link_down: bool) -> Dict[str, Any]:
        """Toggle network link_down state (cable unplug simulation)
        
        NS: This is hot-pluggable on QEMU - no VM restart needed!
        Useful for testing failover scenarios or isolating VMs temporarily.
        
        MK: The trick is to get the current net config, then modify just the link_down part
        while keeping everything else (bridge, mac, model, etc.) intact.
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            
            # First get current network config
            config_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            config_response = self._api_get(config_url)
            
            if config_response.status_code != 200:
                return {'success': False, 'error': 'Could not get VM config'}
            
            vm_config = config_response.json().get('data', {})
            current_net = vm_config.get(net_id, '')
            
            if not current_net:
                return {'success': False, 'error': f'Network {net_id} not found'}
            
            # Parse current network string (e.g. "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1")
            # and modify link_down parameter
            parts = current_net.split(',')
            new_parts = []
            found_link_down = False
            
            for part in parts:
                if part.startswith('link_down='):
                    found_link_down = True
                    if link_down:
                        new_parts.append('link_down=1')
                    # If link_down=False, we just don't add it (remove from config)
                else:
                    new_parts.append(part)
            
            # Add link_down=1 if not found and we want it
            if link_down and not found_link_down:
                new_parts.append('link_down=1')
            
            new_net_config = ','.join(new_parts)
            
            # Update the network config
            update_url = f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/config"
            response = self._api_put(update_url, data={net_id: new_net_config})
            
            if response.status_code == 200:
                action = 'disconnected' if link_down else 'connected'
                self.logger.info(f"[OK] Network {net_id} {action} on QEMU/{vmid}")
                return {'success': True, 'message': f'Network {net_id} {action}'}
            else:
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            self.logger.error(f"[ERROR] Toggle network link failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_cpu_types(self) -> List[str]:
        
        return [
            'host', 'kvm64', 'kvm32', 'qemu64', 'qemu32', 
            'max', 'x86-64-v2', 'x86-64-v2-AES', 'x86-64-v3', 'x86-64-v4',
            'Broadwell', 'Broadwell-IBRS', 'Broadwell-noTSX', 'Broadwell-noTSX-IBRS',
            'Cascadelake-Server', 'Cascadelake-Server-noTSX', 'Cascadelake-Server-v2',
            'Conroe', 'Cooperlake', 'Cooperlake-v2',
            'EPYC', 'EPYC-IBPB', 'EPYC-Milan', 'EPYC-Rome', 'EPYC-v3',
            'Haswell', 'Haswell-IBRS', 'Haswell-noTSX', 'Haswell-noTSX-IBRS',
            'Icelake-Client', 'Icelake-Client-noTSX', 'Icelake-Server', 'Icelake-Server-noTSX',
            'IvyBridge', 'IvyBridge-IBRS',
            'Nehalem', 'Nehalem-IBRS',
            'Opteron_G1', 'Opteron_G2', 'Opteron_G3', 'Opteron_G4', 'Opteron_G5',
            'Penryn', 'SandyBridge', 'SandyBridge-IBRS',
            'SapphireRapids', 'Skylake-Client', 'Skylake-Client-IBRS', 
            'Skylake-Server', 'Skylake-Server-IBRS', 'Skylake-Server-noTSX-IBRS',
            'Westmere', 'Westmere-IBRS', 'athlon', 'core2duo', 'coreduo',
            'n270', 'pentium', 'pentium2', 'pentium3', 'phenom'
        ]
    
    def get_scsi_controllers(self) -> List[Dict]:
        
        return [
            {'value': 'virtio-scsi-pci', 'label': 'VirtIO SCSI'},
            {'value': 'virtio-scsi-single', 'label': 'VirtIO SCSI Single'},
            {'value': 'lsi', 'label': 'LSI 53C895A'},
            {'value': 'lsi53c810', 'label': 'LSI 53C810'},
            {'value': 'megasas', 'label': 'MegaRAID SAS 8708EM2'},
            {'value': 'pvscsi', 'label': 'VMware PVSCSI'},
        ]
    
    def get_network_models(self) -> List[Dict]:
        
        return [
            {'value': 'virtio', 'label': 'VirtIO (paravirtualized)'},
            {'value': 'e1000', 'label': 'Intel E1000'},
            {'value': 'e1000e', 'label': 'Intel E1000E'},
            {'value': 'vmxnet3', 'label': 'VMware vmxnet3'},
            {'value': 'rtl8139', 'label': 'Realtek RTL8139'},
            {'value': 'ne2k_pci', 'label': 'NE2000 PCI'},
            {'value': 'pcnet', 'label': 'AMD PCnet'},
        ]
    
    def get_disk_bus_types(self) -> List[Dict]:
        
        return [
            {'value': 'scsi', 'label': 'SCSI', 'max': 30},
            {'value': 'virtio', 'label': 'VirtIO Block', 'max': 15},
            {'value': 'sata', 'label': 'SATA', 'max': 5},
            {'value': 'ide', 'label': 'IDE', 'max': 3},
        ]
    
    def get_cache_modes(self) -> List[Dict]:
        
        return [
            {'value': '', 'label': 'Default (No cache)'},
            {'value': 'none', 'label': 'No cache'},
            {'value': 'writethrough', 'label': 'Write through'},
            {'value': 'writeback', 'label': 'Write back'},
            {'value': 'unsafe', 'label': 'Write back (unsafe)'},
            {'value': 'directsync', 'label': 'Direct sync'},
        ]
    
    def get_machine_types(self) -> List[Dict]:
        """Get available QEMU machine types
        
        MK: q35 is recommended for modern systems (PCIe native)
        i440fx is the legacy fallback for older guests
        Updated Jan 2026 to include all versions from Proxmox 8.x
        """
        return [
            {'value': '', 'label': 'Default'},
            # q35 versions (modern, PCIe native)
            {'value': 'q35', 'label': 'q35 (Latest)'},
            {'value': 'pc-q35-10.1', 'label': 'q35 10.1'},
            {'value': 'pc-q35-10.0+pve1', 'label': 'q35 10.0+pve1'},
            {'value': 'pc-q35-10.0', 'label': 'q35 10.0'},
            {'value': 'pc-q35-9.2+pve1', 'label': 'q35 9.2+pve1'},
            {'value': 'pc-q35-9.2', 'label': 'q35 9.2'},
            {'value': 'pc-q35-9.1', 'label': 'q35 9.1'},
            {'value': 'pc-q35-9.0', 'label': 'q35 9.0'},
            {'value': 'pc-q35-8.2', 'label': 'q35 8.2'},
            {'value': 'pc-q35-8.1', 'label': 'q35 8.1'},
            {'value': 'pc-q35-8.0', 'label': 'q35 8.0'},
            {'value': 'pc-q35-7.2', 'label': 'q35 7.2'},
            {'value': 'pc-q35-7.1', 'label': 'q35 7.1'},
            {'value': 'pc-q35-7.0', 'label': 'q35 7.0'},
            {'value': 'pc-q35-6.2', 'label': 'q35 6.2'},
            {'value': 'pc-q35-6.1', 'label': 'q35 6.1'},
            {'value': 'pc-q35-6.0', 'label': 'q35 6.0'},
            {'value': 'pc-q35-5.2', 'label': 'q35 5.2'},
            {'value': 'pc-q35-5.1', 'label': 'q35 5.1'},
            {'value': 'pc-q35-5.0', 'label': 'q35 5.0'},
            {'value': 'pc-q35-4.2', 'label': 'q35 4.2'},
            {'value': 'pc-q35-4.1', 'label': 'q35 4.1'},
            {'value': 'pc-q35-4.0', 'label': 'q35 4.0'},
            {'value': 'pc-q35-3.1', 'label': 'q35 3.1'},
            {'value': 'pc-q35-3.0', 'label': 'q35 3.0'},
            {'value': 'pc-q35-2.12', 'label': 'q35 2.12'},
            {'value': 'pc-q35-2.11', 'label': 'q35 2.11'},
            {'value': 'pc-q35-2.10', 'label': 'q35 2.10'},
            # i440fx versions (legacy PCI)
            {'value': 'i440fx', 'label': 'i440fx (Latest)'},
            {'value': 'pc-i440fx-10.1', 'label': 'i440fx 10.1'},
            {'value': 'pc-i440fx-10.0+pve1', 'label': 'i440fx 10.0+pve1'},
            {'value': 'pc-i440fx-10.0', 'label': 'i440fx 10.0'},
            {'value': 'pc-i440fx-9.2+pve1', 'label': 'i440fx 9.2+pve1'},
            {'value': 'pc-i440fx-9.2', 'label': 'i440fx 9.2'},
            {'value': 'pc-i440fx-9.1', 'label': 'i440fx 9.1'},
            {'value': 'pc-i440fx-9.0', 'label': 'i440fx 9.0'},
            {'value': 'pc-i440fx-8.2', 'label': 'i440fx 8.2'},
            {'value': 'pc-i440fx-8.1', 'label': 'i440fx 8.1'},
            {'value': 'pc-i440fx-8.0', 'label': 'i440fx 8.0'},
            {'value': 'pc-i440fx-7.2', 'label': 'i440fx 7.2'},
            {'value': 'pc-i440fx-7.1', 'label': 'i440fx 7.1'},
            {'value': 'pc-i440fx-7.0', 'label': 'i440fx 7.0'},
            {'value': 'pc-i440fx-6.2', 'label': 'i440fx 6.2'},
            {'value': 'pc-i440fx-6.1', 'label': 'i440fx 6.1'},
            {'value': 'pc-i440fx-6.0', 'label': 'i440fx 6.0'},
            {'value': 'pc-i440fx-5.2', 'label': 'i440fx 5.2'},
            {'value': 'pc-i440fx-5.1', 'label': 'i440fx 5.1'},
            {'value': 'pc-i440fx-5.0', 'label': 'i440fx 5.0'},
            {'value': 'pc-i440fx-4.2', 'label': 'i440fx 4.2'},
            {'value': 'pc-i440fx-4.1', 'label': 'i440fx 4.1'},
            {'value': 'pc-i440fx-4.0', 'label': 'i440fx 4.0'},
            {'value': 'pc-i440fx-3.1', 'label': 'i440fx 3.1'},
            {'value': 'pc-i440fx-3.0', 'label': 'i440fx 3.0'},
            {'value': 'pc-i440fx-2.12', 'label': 'i440fx 2.12'},
            {'value': 'pc-i440fx-2.11', 'label': 'i440fx 2.11'},
            {'value': 'pc-i440fx-2.10', 'label': 'i440fx 2.10'},
        ]
    
    # ==================== NODE MANAGEMENT METHODS ====================
    
    def get_node_summary(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            # Get node status
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/status"
            response = self._api_get(url)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Get PVE version
                version_url = f"https://{self.host}:8006/api2/json/nodes/{node}/version"
                version_response = self._create_session().get(version_url, timeout=15)
                version_data = {}
                if version_response.status_code == 200:
                    version_data = version_response.json().get('data', {})
                
                return {
                    'node': node,
                    'status': 'online',
                    'uptime': data.get('uptime', 0),
                    'cpu': data.get('cpu', 0),
                    'cpuinfo': data.get('cpuinfo', {}),
                    'memory': {
                        'total': data.get('memory', {}).get('total', 0),
                        'used': data.get('memory', {}).get('used', 0),
                        'free': data.get('memory', {}).get('free', 0),
                    },
                    'swap': {
                        'total': data.get('swap', {}).get('total', 0),
                        'used': data.get('swap', {}).get('used', 0),
                        'free': data.get('swap', {}).get('free', 0),
                    },
                    'rootfs': {
                        'total': data.get('rootfs', {}).get('total', 0),
                        'used': data.get('rootfs', {}).get('used', 0),
                        'free': data.get('rootfs', {}).get('free', 0),
                    },
                    'loadavg': data.get('loadavg', [0, 0, 0]),
                    'kversion': data.get('kversion', ''),
                    'pveversion': version_data.get('version', ''),
                    'maintenance_mode': node in self.nodes_in_maintenance,
                }
            return {}
        except Exception as e:
            self.logger.error(f"Error getting node summary: {e}")
            return {}
    
    def get_node_rrddata(self, node: str, timeframe: str = 'hour') -> Dict[str, Any]:
        """Get node performance metrics (RRD data) for charts
        
        NS: Added Jan 2026 - Same format as VM rrddata for consistency
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect to Proxmox'}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/rrddata"
            
            response = self._create_session().get(url, params={'timeframe': timeframe})
            
            if response.status_code == 200:
                rrd_data = response.json().get('data', [])
                
                # Process and format the data for charts
                formatted_data = {
                    'timeframe': timeframe,
                    'node': node,
                    'metrics': {
                        'cpu': [],
                        'memory': [],
                        'swap': [],
                        'iowait': [],
                        'loadavg': [],
                        'net_in': [],
                        'net_out': [],
                        'rootfs': []
                    },
                    'timestamps': []
                }

                # Check for pressure stall data (PSI)
                pressure_keys = [
                    'pressurecpusome', 'pressurecpufull',
                    'pressurememorysome', 'pressurememoryfull',
                    'pressureiosome', 'pressureiofull'
                ]
                active_pressure_keys = []

                # Check first valid point to determine available metrics
                if rrd_data:
                    first_point = next((p for p in rrd_data if p), None)
                    if first_point:
                        for k in pressure_keys:
                            if k in first_point:
                                active_pressure_keys.append(k)
                                formatted_data['metrics'][k] = []

                for point in rrd_data:
                    if not point:
                        continue
                    
                    timestamp = point.get('time', 0)
                    formatted_data['timestamps'].append(timestamp)
                    
                    # CPU usage (0-1 -> 0-100%)
                    cpu = point.get('cpu', 0)
                    formatted_data['metrics']['cpu'].append(round((cpu or 0) * 100, 2))
                    
                    # IO Wait
                    iowait = point.get('iowait', 0)
                    formatted_data['metrics']['iowait'].append(round((iowait or 0) * 100, 2))
                    
                    # Memory usage
                    memused = point.get('memused', 0)
                    memtotal = point.get('memtotal', 1)
                    mem_percent = ((memused or 0) / (memtotal or 1)) * 100
                    formatted_data['metrics']['memory'].append(round(mem_percent, 2))
                    
                    # Swap usage
                    swapused = point.get('swapused', 0)
                    swaptotal = point.get('swaptotal', 1)
                    if swaptotal and swaptotal > 0:
                        swap_percent = ((swapused or 0) / swaptotal) * 100
                    else:
                        swap_percent = 0
                    formatted_data['metrics']['swap'].append(round(swap_percent, 2))
                    
                    # Load average
                    loadavg = point.get('loadavg', 0)
                    formatted_data['metrics']['loadavg'].append(round(loadavg or 0, 2))
                    
                    # Network I/O (bytes/s)
                    netin = point.get('netin', 0)
                    netout = point.get('netout', 0)
                    formatted_data['metrics']['net_in'].append(round((netin or 0) / 1024, 2))  # KB/s
                    formatted_data['metrics']['net_out'].append(round((netout or 0) / 1024, 2))  # KB/s
                    
                    # Root FS usage
                    rootused = point.get('rootused', 0)
                    roottotal = point.get('roottotal', 1)
                    if roottotal and roottotal > 0:
                        rootfs_percent = ((rootused or 0) / roottotal) * 100
                    else:
                        rootfs_percent = 0
                    formatted_data['metrics']['rootfs'].append(round(rootfs_percent, 2))

                    # Pressure Stall (PSI)
                    for k in active_pressure_keys:
                        formatted_data['metrics'][k].append(point.get(k, 0) or 0)
                
                return formatted_data
            return {'error': 'Failed to get RRD data'}
        except Exception as e:
            self.logger.error(f"Error getting node RRD data: {e}")
            return {'error': str(e)}
    
    def get_node_network_config(self, node: str) -> List[Dict]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting network config: {e}")
            return []
    
    def update_node_network(self, node: str, iface: str, config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network/{iface}"
            response = self._api_put(url, data=config)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Network updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_node_network(self, node: str, iface: str, iface_type: str, config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network"
            data = {
                'iface': iface,
                'type': iface_type,
                **config
            }
            # Remove empty values
            data = {k: v for k, v in data.items() if v is not None and v != ''}
            
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'message': f'Interface {iface} created'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_node_network(self, node: str, iface: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network/{iface}"
            response = self._api_delete(url)
            
            if response.status_code == 200:
                return {'success': True, 'message': f'Interface {iface} deleted'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def apply_node_network(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network"
            response = self._create_session().put(url, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Network changes applied'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def revert_node_network(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/network"
            response = self._api_delete(url)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Network changes reverted'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_dns(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/dns"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting DNS config: {e}")
            return {}
    
    def update_node_dns(self, node: str, dns_config: Dict) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/dns"
            response = self._api_put(url, data=dns_config)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'DNS updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_hosts(self, node: str) -> str:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return ''
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/hosts"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('data', '')
            return ''
        except Exception as e:
            self.logger.error(f"Error getting hosts: {e}")
            return ''
    
    def update_node_hosts(self, node: str, hosts_content: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/hosts"
            response = self._api_post(url, data={'data': hosts_content})
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Hosts updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_time(self, node: str) -> Dict[str, Any]:
        
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/time"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting time: {e}")
            return {}
    
    def update_node_time(self, node: str, timezone: str) -> Dict[str, Any]:
        """Update node timezone"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/time"
            response = self._api_put(url, data={'timezone': timezone})
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Timezone updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_syslog(self, node: str, start: int = 0, limit: int = 500, since: int = 0) -> List[str]:
        """Get node system log - returns newest entries first"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/syslog"
            params = {'limit': limit}
            if since:
                params['since'] = since
            response = self._create_session().get(url, params=params)
            
            if response.status_code == 200:
                data = response.json().get('data', [])
                # Reverse to get newest first, then return
                lines = [line.get('t', '') for line in data]
                return list(reversed(lines))
            return []
        except Exception as e:
            self.logger.error(f"Error getting syslog: {e}")
            return []
    
    def get_node_certificates(self, node: str) -> List[Dict]:
        """Get node certificates"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/certificates/info"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting certificates: {e}")
            return []
    
    def renew_node_certificate(self, node: str, force: bool = False) -> Dict[str, Any]:
        """Renew node certificate using ACME"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/certificates/acme/certificate"
            data = {'force': 1} if force else {}
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def upload_node_certificate(self, node: str, certificates: str, key: str, restart: bool = True, force: bool = False) -> Dict[str, Any]:
        """Upload custom certificate to node"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/certificates/custom"
            data = {
                'certificates': certificates,
                'key': key,
                'restart': 1 if restart else 0,
                'force': 1 if force else 0
            }
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Certificate uploaded successfully'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_node_certificate(self, node: str, restart: bool = True) -> Dict[str, Any]:
        """Delete custom certificate from node (reverts to self-signed)"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/certificates/custom"
            params = {'restart': 1 if restart else 0}
            response = self._create_session().delete(url, params=params)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Certificate deleted'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_disks(self, node: str) -> List[Dict]:
        """Get physical disks on node"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/list"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting disks: {e}")
            return []
    
    def get_node_disk_smart(self, node: str, disk: str) -> Dict[str, Any]:
        """Get SMART data for a disk"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/smart"
            response = self._create_session().get(url, params={'disk': disk})
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting SMART data: {e}")
            return {}
    
    def get_node_lvm(self, node: str) -> List[Dict]:
        """Get LVM volume groups"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/lvm"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting LVM: {e}")
            return []
    
    def create_node_lvm(self, node: str, device: str, name: str, add_storage: bool = True) -> Dict[str, Any]:
        """Create LVM volume group"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/lvm"
            data = {
                'device': device,
                'name': name,
                'add_storage': 1 if add_storage else 0
            }
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_lvmthin(self, node: str) -> List[Dict]:
        """Get LVM-Thin pools"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/lvmthin"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting LVM-Thin: {e}")
            return []
    
    def create_node_lvmthin(self, node: str, device: str, name: str, add_storage: bool = True) -> Dict[str, Any]:
        """Create LVM-Thin pool"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/lvmthin"
            data = {
                'device': device,
                'name': name,
                'add_storage': 1 if add_storage else 0
            }
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_zfs(self, node: str) -> List[Dict]:
        """Get ZFS pools"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/zfs"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting ZFS: {e}")
            return []
    
    def create_node_zfs(self, node: str, name: str, devices: list, raidlevel: str = 'single', 
                         compression: str = 'on', ashift: int = 12, add_storage: bool = True) -> Dict[str, Any]:
        """create ZFS pool on node. NS Dec 2025: added compression + ashift support"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/zfs"
            
            # devices must be comma-separated string for Proxmox API
            if isinstance(devices, list):
                devices_str = ' '.join(devices)
            else:
                devices_str = devices
            
            data = {
                'name': name,
                'devices': devices_str,
                'raidlevel': raidlevel,
                'compression': compression,
                'ashift': ashift,
                'add_storage': 1 if add_storage else 0
            }
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_directory_storage(self, node: str) -> List[Dict]:
        """Get directory storage locations"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/directory"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting directory storage: {e}")
            return []
    
    def create_node_directory(self, node: str, device: str, name: str, filesystem: str = 'ext4', add_storage: bool = True) -> Dict[str, Any]:
        """Create directory storage"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/directory"
            data = {
                'device': device,
                'name': name,
                'filesystem': filesystem,
                'add_storage': 1 if add_storage else 0
            }
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def init_disk_gpt(self, node: str, disk: str, uuid: str = None) -> Dict[str, Any]:
        """Initialize disk with GPT partition table"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/initgpt"
            data = {'disk': disk}
            if uuid:
                data['uuid'] = uuid
            response = self._api_post(url, data=data)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def wipe_disk(self, node: str, disk: str) -> Dict[str, Any]:
        """Wipe disk (remove partition table)"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/disks/wipedisk"
            response = self._api_post(url, data={'disk': disk})
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_replication(self, node: str) -> List[Dict]:
        """Get replication jobs for node"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/replication"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting replication: {e}")
            return []
    
    def get_node_tasks(self, node: str, start: int = 0, limit: int = 50, errors: bool = False) -> List[Dict]:
        """Get task history for node"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/tasks"
            params = {'start': start, 'limit': limit}
            if errors:
                params['errors'] = 1
            response = self._create_session().get(url, params=params)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.logger.error(f"Error getting tasks: {e}")
            return []
    
    def get_node_task_log(self, node: str, upid: str, start: int = 0, limit: int = 500) -> List[str]:
        """Get log for a specific task"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return []
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/tasks/{upid}/log"
            response = self._create_session().get(url, params={'start': start, 'limit': limit})
            
            if response.status_code == 200:
                data = response.json().get('data', [])
                return [line.get('t', '') for line in data]
            return []
        except Exception as e:
            self.logger.error(f"Error getting task log: {e}")
            return []
    
    def get_node_subscription(self, node: str) -> Dict[str, Any]:
        """Get node subscription status"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/subscription"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting subscription: {e}")
            return {}
    
    def update_node_subscription(self, node: str, key: str) -> Dict[str, Any]:
        """Update subscription key"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/subscription"
            response = self._api_put(url, data={'key': key})
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Subscription updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_options(self, node: str) -> Dict[str, Any]:
        """Get node options (from datacenter)"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {}
        
        try:
            # Node options are part of datacenter config for that node
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/config"
            response = self._api_get(url)
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return {}
        except Exception as e:
            self.logger.error(f"Error getting node options: {e}")
            return {}
    
    def update_node_options(self, node: str, options: Dict) -> Dict[str, Any]:
        """Update node options"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            url = f"https://{self.host}:8006/api2/json/nodes/{node}/config"
            response = self._api_put(url, data=options)
            
            if response.status_code == 200:
                return {'success': True, 'message': 'Options updated'}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_node_apt_updates(self, node: str) -> List[Dict]:
        """Get available APT updates
        
        MK: Feb 2026 - Raises exception on failure instead of returning []
        so the caller can distinguish 'no updates' from 'check failed'
        """
        if not self.is_connected:
            if not self.connect_to_proxmox():
                raise ConnectionError(f"Not connected to cluster")
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/apt/update"
            response = self._create_session().get(url, timeout=15)
            
            if response.status_code == 200:
                return response.json().get('data', [])
            # NS: Don't silently return [] - let the caller know it failed
            raise Exception(f"API returned {response.status_code}")
        except ConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting APT updates for {node}: {e}")
            raise
    
    def refresh_node_apt(self, node: str) -> Dict[str, Any]:
        """Refresh APT package database"""
        if not self.is_connected:
            if not self.connect_to_proxmox():
                return {'success': False, 'error': 'Could not connect'}
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/nodes/{node}/apt/update"
            response = self._create_session().post(url, timeout=15)
            
            if response.status_code == 200:
                return {'success': True, 'task': response.json().get('data')}
            return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_timezones(self) -> List[str]:
        """Get list of available timezones"""
        return [
            'UTC', 'Europe/Berlin', 'Europe/Vienna', 'Europe/Zurich', 'Europe/London',
            'Europe/Paris', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Rome',
            'Europe/Madrid', 'Europe/Warsaw', 'Europe/Prague', 'Europe/Budapest',
            'Europe/Stockholm', 'Europe/Helsinki', 'Europe/Athens', 'Europe/Moscow',
            'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
            'America/Toronto', 'America/Vancouver', 'America/Sao_Paulo', 'America/Mexico_City',
            'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore', 'Asia/Seoul',
            'Asia/Dubai', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Jakarta',
            'Australia/Sydney', 'Australia/Melbourne', 'Australia/Perth',
            'Pacific/Auckland', 'Pacific/Fiji',
            'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Lagos',
        ]

    # ==================== END NODE MANAGEMENT METHODS ====================
    
    def run_balance_check(self):
        """
        Run a single balance check iteration
        
        NS: This is the main loadbalancer logic - runs every check_interval seconds
        1. Get node scores (CPU + RAM weighted)
        2. If difference > threshold, find a VM to migrate
        3. Move smallest suitable VM from loaded -> less loaded node
        
        MK: Feb 2026 - Now supports up to 3 migrations per cycle for larger clusters.
        After each migration, scores are re-evaluated to avoid over-correcting.
        LW: Number of migrations scales with score difference and cluster size.
        """
        try:
            self.logger.info("=" * 60)
            self.logger.info(f"Starting balance check for cluster: {self.config.name}")
            self.logger.info(f"Settings: Migration Threshold={self.config.migration_threshold}%, Check Interval={self.config.check_interval}s, Dry Run={self.config.dry_run}")
            
            # Get node status
            node_status = self.get_node_status()
            if not node_status:
                self.logger.warning("Could not get node status")
                return
            
            # Log nodes in maintenance
            maintenance_nodes = [n for n, d in node_status.items() if d.get('maintenance_mode')]
            if maintenance_nodes:
                self.logger.info(f"[MAINT] Nodes in maintenance: {', '.join(maintenance_nodes)}")
            
            # NS: Calculate max migrations per cycle based on cluster size and score diff
            # Small clusters (2-3 nodes): max 1 migration
            # Medium clusters (4-6 nodes): max 2 migrations
            # Large clusters (7+ nodes): max 3 migrations
            config_excluded = getattr(self.config, 'excluded_nodes', []) or []
            active_node_count = sum(
                1 for n, d in node_status.items() 
                if d['status'] == 'online' 
                and not d.get('maintenance_mode', False) 
                and n not in config_excluded
            )
            
            if active_node_count >= 7:
                max_migrations = 3
            elif active_node_count >= 4:
                max_migrations = 2
            else:
                max_migrations = 1
            
            self.logger.info(f"Active nodes: {active_node_count}, Max migrations per cycle: {max_migrations}")
            
            migrations_done = 0
            already_migrated_vmids = []  # LW: Track migrated VMs to avoid picking same one
            
            for migration_round in range(max_migrations):
                # Re-fetch node status after each migration (scores changed!)
                if migration_round > 0:
                    self.logger.info(f"--- Re-evaluating balance (round {migration_round + 1}/{max_migrations}) ---")
                    node_status = self.get_node_status()
                    if not node_status:
                        break
                
                # Check if balancing is needed
                needs_balance, source_node, target_node = self.check_balance_needed(node_status)
                
                if not needs_balance:
                    if migration_round == 0:
                        pass  # Normal - already logged in check_balance_needed
                    else:
                        self.logger.info(f"[OK] Cluster balanced after {migrations_done} migration(s)")
                    break
                
                if not self.config.auto_migrate:
                    break
                
                # MK: Find migration candidate, excluding already migrated VMs
                vm = self.find_migration_candidate(source_node, target_node, exclude_vmids=already_migrated_vmids)
                
                if vm:
                    vmid = vm.get('vmid')
                    vm_name = vm.get('name', 'unnamed')
                    
                    if max_migrations > 1:
                        self.logger.info(f"[{migration_round + 1}/{max_migrations}] Migrating {vm_name} (VMID {vmid}): {source_node} → {target_node}")
                    
                    success = self.migrate_vm(vm, target_node)
                    
                    if success:
                        migrations_done += 1
                        already_migrated_vmids.append(vmid)
                    else:
                        self.logger.warning(f"Migration failed for {vm_name}, stopping further migrations this cycle")
                        break
                else:
                    self.logger.info("No suitable VM found for migration")
                    break
            
            if migrations_done > 1:
                self.logger.info(f"[SUMMARY] Completed {migrations_done} migration(s) in this cycle")
            
            self.last_run = datetime.now()
            self.logger.info(f"Balance check completed at {self.last_run}")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"Error in balance check: {e}")
    
    def daemon_loop(self):
        """Main daemon loop"""
        self.logger.info(f"PegaProx daemon started for cluster: {self.config.name}")
        
        # Initial connection with auto-discovery
        if not self.connect_to_proxmox():
            self.logger.error("Initial connection failed, will retry...")
        
        while not self.stop_event.is_set():
            if self.config.enabled:
                # Check connection and reconnect if needed
                if not self._check_connection():
                    self.logger.warning("Connection lost, attempting reconnect...")
                    self.session = None
                    if self.connect_to_proxmox():
                        self.logger.info("Reconnected successfully")
                    else:
                        self.logger.error("Reconnect failed, will retry next cycle")
                
                self.run_balance_check()
            else:
                # LW: Even when disabled, still verify connection for UI status
                # Just less frequently - only every 5th cycle
                self._disabled_check_counter += 1
                
                if self._disabled_check_counter >= 5:
                    self._disabled_check_counter = 0
                    if not self._check_connection():
                        # Try to reconnect silently
                        self.session = None
                        self.connect_to_proxmox()
                
                self.logger.debug("PegaProx is disabled, skipping check")
            
            # Wait for next interval or stop signal
            self.stop_event.wait(self.config.check_interval)
        
        self.logger.info(f"PegaProx daemon stopped for cluster: {self.config.name}")
    
    def _check_connection(self) -> bool:
        """Check if connection to Proxmox is still alive"""
        if not self.is_connected:
            return False
        
        try:
            host = self.current_host or self.config.host
            url = f"https://{host}:8006/api2/json/version"
            response = self._create_session().get(url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def start(self):
        """Start the PegaProx daemon"""
        if self.running:
            return
        
        self.stop_event.clear()
        self.thread = threading.Thread(target=self.daemon_loop)
        self.thread.daemon = True
        self.thread.start()
        self.running = True
        self.logger.info(f"Started PegaProx manager for {self.config.name}")
        
        # Start HA monitor if enabled
        if self.config.ha_enabled:
            self.start_ha_monitor()
    
    def stop(self):
        """Stop the PegaProx daemon"""
        if not self.running:
            return
        
        # Stop HA monitor
        self.stop_ha_monitor()
        
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
        self.running = False
        self.logger.info(f"Stopped PegaProx manager for {self.config.name}")

