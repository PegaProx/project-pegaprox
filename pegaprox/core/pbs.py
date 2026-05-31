# -*- coding: utf-8 -*-
"""
PegaProx PBS Manager - Layer 5
Proxmox Backup Server integration.
"""

import os
import json
import time
import logging
import threading
import requests
from datetime import datetime
import urllib3
from typing import List, Optional
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pegaprox.core.db import get_db
from pegaprox.globals import pbs_managers

def _validate_pbs_host(host: str) -> bool:
    """Validate PBS host against allowlist.
    
    Returns True if host is allowed, False otherwise.
    """
    # Domain allowlist - add your allowed PBS server domains here
    allowed_domains = ['example.com']  # add your allowed domains here
    
    if not host:
        return False
    
    # Validate host format (hostname or IP, no protocol/path)
    # Allow alphanumeric, dots, hyphens, and colons (for IPv6)
    if not re.match(r'^[a-zA-Z0-9\.\-\:]+$', host):
        return False
    
    # Check if host matches any allowed domain (exact match or subdomain)
    for allowed_domain in allowed_domains:
        if host == allowed_domain or host.endswith('.' + allowed_domain):
            return True
    
    return False

class PBSManager:
    """Manages connection to a Proxmox Backup Server instance
    
    NS: PBS uses the same REST API pattern as PVE but on port 8007
    Auth: ticket-based (like PVE) or API token header
    MK: API token format: PBSAPIToken=user@realm!tokenname:secret
    """
    
    def __init__(self, pbs_id: str, config: dict):
        self.id = pbs_id
        self.name = config.get('name', 'PBS')
        self.host = config.get('host', '')
        self.port = int(config.get('port', 8007))
        self.user = config.get('user', 'root@pam')
        self.password = config.get('password', '')
        self.api_token_id = config.get('api_token_id', '')  # user@realm!tokenname
        self.api_token_secret = config.get('api_token_secret', '')
        self.fingerprint = config.get('fingerprint', '')
        self.ssl_verify = config.get('ssl_verify', False)
        self.linked_clusters = config.get('linked_clusters', [])
        self.enabled = config.get('enabled', True)
        self.notes = config.get('notes', '')
        # NS Apr 2026: SSH credentials for remote apt-get upgrade (PBS API has no upgrade endpoint)
        self.ssh_user = config.get('ssh_user', '') or ''
        self.ssh_port = int(config.get('ssh_port', 22) or 22)
        self.ssh_key = config.get('ssh_key', '') or ''
        self._update_task = None  # active UpdateTask or None

        # Validate host against allowlist
        if not _validate_pbs_host(self.host):
            raise ValueError(f"Invalid or disallowed PBS host")

        self._session = requests.Session()
        self._session.verify = self.ssl_verify
        self._ticket = None
        self._csrf_token = None
        self._using_api_token = bool(self.api_token_id and self.api_token_secret)
        self._ticket_time = 0
        self.connected = False
        self.last_error = ''
        self.last_status = {}
        self._lock = threading.Lock()
        
        # Disable SSL warnings if not verifying
        if not self.ssl_verify:
            self._session.verify = False
    
    @property
    def base_url(self):
        return f"https://{self.host}:{self.port}/api2/json"
    
    def connect(self) -> bool:
        """Authenticate with PBS server
        
        NS: Try API token first (stateless), fall back to ticket auth
        """
        try:
            if self._using_api_token:
                # API Token auth - just verify it works
                self._session.headers['Authorization'] = f"PBSAPIToken={self.api_token_id}:{self.api_token_secret}"
                resp = self._session.get(f"{self.base_url}/version", timeout=10)
                if resp.status_code == 200:
                    self.connected = True
                    self.last_error = ''
                    data = resp.json().get('data', {})
                    logging.info(f"[PBS:{self.name}] Connected via API token (version {data.get('version', '?')})")
                    return True
                else:
                    self.last_error = f"API token auth failed: HTTP {resp.status_code}"
                    logging.warning(f"[PBS:{self.name}] {self.last_error}")
                    self.connected = False
                    return False
            else:
                # Ticket auth (like PVE)
                resp = self._session.post(f"{self.base_url}/access/ticket", data={
                    'username': self.user,
                    'password': self.password,
                }, timeout=10)
                
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    self._ticket = data.get('ticket', '')
                    self._csrf_token = data.get('CSRFPreventionToken', '')
                    self._ticket_time = time.time()
                    
                    # Set auth headers
                    self._session.cookies.set('PBSAuthCookie', self._ticket)
                    self._session.headers['CSRFPreventionToken'] = self._csrf_token
                    
                    self.connected = True
                    self.last_error = ''
                    logging.info(f"[PBS:{self.name}] Connected via ticket auth (user: {self.user})")
                    return True
                else:
                    self.last_error = f"Ticket auth failed: HTTP {resp.status_code}"
                    logging.warning(f"[PBS:{self.name}] {self.last_error}")
                    self.connected = False
                    return False
                    
        except requests.exceptions.ConnectionError as e:
            self.last_error = f"Connection failed: {self.host}:{self.port}"
            logging.error(f"[PBS:{self.name}] {self.last_error}")
            self.connected = False
            return False
        except Exception as e:
            self.last_error = str(e)
            logging.error(f"[PBS:{self.name}] Connect error: {e}")
            self.connected = False
            return False
    
    def _ensure_ticket(self):
        """Refresh ticket if older than 90 minutes (PBS tickets expire after 2h)"""
        if not self._using_api_token and self._ticket:
            if time.time() - self._ticket_time > 5400:  # 90 min
                self.connect()
    
    def api_get(self, path: str, params: dict = None, timeout: int = 30) -> dict:
        """GET request to PBS API"""
        self._ensure_ticket()
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._session.get(url, params=params, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                # Token expired, try reconnect
                if self.connect():
                    resp = self._session.get(url, params=params, timeout=timeout)
                    if resp.status_code == 200:
                        return resp.json()
            logging.warning(f"[PBS:{self.name}] GET {path} → {resp.status_code}")
            return {'error': f"HTTP {resp.status_code}", 'status_code': resp.status_code}
        except Exception as e:
            logging.error(f"[PBS:{self.name}] GET {path} failed: {e}")
            return {'error': str(e)}
    
    def api_post(self, path: str, data: dict = None) -> dict:
        """POST request to PBS API"""
        self._ensure_ticket()
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._session.post(url, json=data, timeout=60)
            if resp.status_code in (200, 201):
                return resp.json()
            elif resp.status_code == 401:
                if self.connect():
                    resp = self._session.post(url, json=data, timeout=60)
                    if resp.status_code in (200, 201):
                        return resp.json()
            logging.warning(f"[PBS:{self.name}] POST {path} → {resp.status_code}")
            try:
                err_body = resp.json()
                return {'error': err_body.get('message', err_body.get('errors', f"HTTP {resp.status_code}"))}
            except Exception:
                return {'error': f"HTTP {resp.status_code}"}
        except Exception as e:
            logging.error(f"[PBS:{self.name}] POST {path} failed: {e}")
            return {'error': str(e)}
    
    def api_put(self, path: str, data: dict = None) -> dict:
        """PUT request to PBS API"""
        self._ensure_ticket()
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._session.put(url, json=data, timeout=60)
            if resp.status_code in (200, 201):
                return resp.json()
            elif resp.status_code == 401:
                if self.connect():
                    resp = self._session.put(url, json=data, timeout=60)
                    if resp.status_code in (200, 201):
                        return resp.json()
            logging.warning(f"[PBS:{self.name}] PUT {path} → {resp.status_code}")
            try:
                err_body = resp.json()
                return {'error': err_body.get('message', err_body.get('errors', f"HTTP {resp.status_code}"))}
            except Exception:
                return {'error': f"HTTP {resp.status_code}"}
        except Exception as e:
            logging.error(f"[PBS:{self.name}] PUT {path} failed: {e}")
            return {'error': str(e)}
    
    def api_get_raw(self, path: str, params: dict = None) -> tuple:
        """GET request returning raw response (for file downloads)"""
        self._ensure_ticket()
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._session.get(url, params=params, timeout=120, stream=True)
            if resp.status_code == 401:
                if self.connect():
                    resp = self._session.get(url, params=params, timeout=120, stream=True)
            return resp
        except Exception as e:
            logging.error(f"[PBS:{self.name}] GET_RAW {path} failed: {e}")
            return None
    
    def api_delete(self, path: str, params: dict = None) -> dict:
        """DELETE request to PBS API"""
        self._ensure_ticket()
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._session.delete(url, params=params, timeout=30)
            if resp.status_code in (200, 204):
                try:
                    return resp.json()
                except Exception:
                    return {'data': None}
            elif resp.status_code == 401:
                if self.connect():
                    resp = self._session.delete(url, params=params, timeout=30)
                    if resp.status_code in (200, 204):
                        try:
                            return resp.json()
                        except Exception:
                            return {'data': None}
            logging.warning(f"[PBS:{self.name}] DELETE {path} → {resp.status_code}")
            return {'error': f"HTTP {resp.status_code}"}
        except Exception as e:
            logging.error(f"[PBS:{self.name}] DELETE {path} failed: {e}")
            return {'error': str(e)}
    
    # ── Status ──
    
    def get_server_status(self) -> dict:
        """Get PBS server status (CPU, RAM, disk, uptime)"""
        result = self.api_get('/nodes/localhost/status')
        if 'error' not in result:
            self.last_status = result.get('data', {})
        return result
    
    def get_version(self) -> dict:
        """Get PBS version info"""
        return self.api_get('/version')
    
    def get_apt_updates(self) -> dict:
        """List available APT updates on PBS host"""
        return self.api_get('/nodes/localhost/apt/update')

    def refresh_apt(self) -> dict:
        """Refresh APT package cache on PBS"""
        return self.api_post('/nodes/localhost/apt/update')

    # ── Update execution via SSH (PBS has no API upgrade endpoint) ──
    def _ssh_connect(self):
        """Open paramiko SSH connection to the PBS host.

        Priority for SSH user:
        1. Explicit ssh_user from config (UI override)
        2. Username from user@realm (password-auth case, e.g. 'root@pam' -> 'root')
        3. Default 'root' (API-token case — token user has no unix account)
        """
        try:
            import paramiko
        except ImportError:
            return None, "paramiko not installed"

        if self.ssh_user:
            ssh_user = self.ssh_user
        elif self._using_api_token:
            # API token users (like 'pegaprox@pbs!tokenname') don't exist as unix users —
            # fall back to 'root' which is the default shell account on PBS
            ssh_user = 'root'
        elif self.user:
            ssh_user = self.user.split('@')[0]  # root@pam -> root
        else:
            ssh_user = 'root'

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # try key-based first if we have one
        if self.ssh_key:
            try:
                from io import StringIO
                key = None
                for KeyClass in [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]:
                    try:
                        key = KeyClass.from_private_key(StringIO(self.ssh_key))
                        break
                    except Exception:
                        continue
                if key:
                    client.connect(self.host, port=self.ssh_port, username=ssh_user,
                                   pkey=key, timeout=15, banner_timeout=15, auth_timeout=15,
                                   allow_agent=False, look_for_keys=False)
                    return client, None
            except Exception as e:
                logging.warning(f"[PBS:{self.name}] SSH key auth failed: {e}")

        # fallback: API password (many PBS installs share system + web password on root@pam)
        if self.password:
            try:
                client.connect(self.host, port=self.ssh_port, username=ssh_user,
                               password=self.password, timeout=15, banner_timeout=15, auth_timeout=15,
                               allow_agent=False, look_for_keys=False)
                return client, None
            except Exception as e:
                return None, f"SSH auth failed for {ssh_user}@{self.host}: {e}"

        return None, f"No SSH credentials configured (ssh_key or password needed)"

    def start_update(self, reboot: bool = False):
        """Kick off apt update + dist-upgrade on the PBS host in a background thread.
        Returns an UpdateTask-like object (subset of what PVE uses)."""
        from pegaprox.models.tasks import UpdateTask
        from pegaprox.utils.concurrent import GEVENT_PATCHED
        import threading as _th

        with self._lock:
            if self._update_task and self._update_task.status in ('starting', 'updating', 'rebooting', 'waiting_online'):
                return self._update_task
            task = UpdateTask(self.name, reboot)
            self._update_task = task

        if GEVENT_PATCHED:
            try:
                import gevent
                gevent.spawn(self._perform_update, task)
                return task
            except Exception:
                pass
        t = _th.Thread(target=self._perform_update, args=(task,), daemon=True)
        t.start()
        return task

    def get_update_status(self):
        return self._update_task

    def clear_update_status(self):
        t = self._update_task
        if t and t.status in ('completed', 'failed'):
            self._update_task = None
            return True
        return False

    def _perform_update(self, task):
        from datetime import datetime
        import time as _t
        ssh = None
        try:
            task.status = 'updating'
            task.phase = 'connecting'
            task.add_output(f"Connecting to PBS {self.host}:{self.ssh_port}...")
            ssh, err = self._ssh_connect()
            if not ssh:
                raise Exception(err or 'SSH connection failed')
            task.add_output("SSH connection established")

            # are we root?
            stdin, stdout, _ = ssh.exec_command('id -u')
            uid = stdout.read().decode().strip()
            sudo = '' if uid == '0' else 'sudo '

            # apt update
            task.phase = 'apt_update'
            task.add_output("Running apt update...")
            stdin, stdout, stderr = ssh.exec_command(f'{sudo}DEBIAN_FRONTEND=noninteractive apt-get update')
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            if rc != 0:
                raise Exception(f"apt update failed (rc={rc}): {err or out[:300]}")
            task.add_output("[OK] apt update successful")

            # apt dist-upgrade
            task.phase = 'apt_dist_upgrade'
            task.add_output("Running apt dist-upgrade...")
            cmd = (f'{sudo}DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y '
                   f'-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"')
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=1800)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            if rc != 0:
                raise Exception(f"dist-upgrade failed (rc={rc}): {err[:400] or out[:400]}")
            # crude counter
            for line in out.splitlines():
                if 'upgraded' in line.lower() and 'newly installed' in line.lower():
                    try:
                        task.packages_upgraded = int(line.split()[0])
                    except Exception:
                        pass
                    break
            task.add_output(f"[OK] dist-upgrade successful ({task.packages_upgraded} packages)")

            # cleanup
            for c in [f'{sudo}apt-get autoremove -y', f'{sudo}apt-get autoclean']:
                stdin, stdout, stderr = ssh.exec_command(c)
                stdout.channel.recv_exit_status()

            # reboot?
            if task.reboot:
                task.phase = 'reboot'
                task.status = 'rebooting'
                task.add_output("Rebooting PBS...")
                try:
                    transport = ssh.get_transport()
                    channel = transport.open_session()
                    channel.get_pty()
                    channel.settimeout(10)
                    channel.exec_command('shutdown -r now' if uid == '0' else 'sudo shutdown -r now')
                    _t.sleep(3)
                    channel.close()
                except Exception:
                    pass  # connection drop during reboot is expected
                try: ssh.close()
                except: pass
                ssh = None
                # wait for reconnect (60-600s window)
                task.phase = 'wait_online'
                task.status = 'waiting_online'
                deadline = _t.time() + 600
                while _t.time() < deadline:
                    _t.sleep(10)
                    test_ssh, terr = self._ssh_connect()
                    if test_ssh:
                        try: test_ssh.close()
                        except: pass
                        task.add_output("[OK] PBS is back online")
                        break
                else:
                    task.status = 'failed'
                    task.error = 'PBS did not come back online within 10 min'
                    task.completed_at = datetime.now()
                    return

            task.status = 'completed'
            task.phase = 'done'
            task.completed_at = datetime.now()
            task.add_output("[OK] Update completed")
        except Exception as e:
            task.status = 'failed'
            task.error = str(e)
            task.add_output(f"[ERROR] {e}")
        finally:
            if ssh:
                try: ssh.close()
                except: pass

    def get_datastore_usage(self) -> dict:
        """Get all datastores usage overview - lightweight endpoint"""
        return self.api_get('/status/datastore-usage')
    
    # ── Datastores ──
    
    def get_datastores(self) -> dict:
        """List all configured datastores"""
        return self.api_get('/config/datastore')
    
    def get_datastore_status(self, store: str) -> dict:
        """Get detailed status of a datastore (usage, GC status, counts)"""
        return self.api_get(f'/admin/datastore/{store}/status')
    
    def get_snapshots(self, store: str, ns: str = None, backup_type: str = None, backup_id: str = None) -> dict:
        """List snapshots in a datastore, optionally filtered by group.
        LW: longer timeout because large datastores can have thousands of entries"""
        params = {}
        if ns:
            params['ns'] = ns
        if backup_type:
            params['backup-type'] = backup_type
        if backup_id:
            params['backup-id'] = backup_id
        return self.api_get(f'/admin/datastore/{store}/snapshots', params=params, timeout=60)
    
    def get_groups(self, store: str, ns: str = None) -> dict:
        """List backup groups (vm/ct/host) in a datastore"""
        params = {}
        if ns:
            params['ns'] = ns
        return self.api_get(f'/admin/datastore/{store}/groups', params=params)
    
    def get_namespaces(self, store: str) -> dict:
        """List namespaces in a datastore"""
        return self.api_get(f'/admin/datastore/{store}/namespace')
    
    # ── Actions ──
    
    def start_gc(self, store: str) -> dict:
        """Start garbage collection on a datastore"""
        return self.api_post(f'/admin/datastore/{store}/gc')
    
    def start_verify(self, store: str, ignore_verified: bool = True) -> dict:
        """Start verification of a datastore"""
        data = {}
        if ignore_verified:
            data['ignore-verified'] = True
        return self.api_post(f'/admin/datastore/{store}/verify', data=data)
    
    def prune_datastore(self, store: str, ns: str = None, keep_last: int = None,
                        keep_daily: int = None, keep_weekly: int = None,
                        keep_monthly: int = None, keep_yearly: int = None,
                        backup_type: str = None, backup_id: str = None,
                        dry_run: bool = True) -> dict:
        """Prune old backups from a datastore
        
        NS: dry_run=True by default for safety!
        """
        data = {}
        if ns:
            data['ns'] = ns
        if keep_last is not None:
            data['keep-last'] = keep_last
        if keep_daily is not None:
            data['keep-daily'] = keep_daily
        if keep_weekly is not None:
            data['keep-weekly'] = keep_weekly
        if keep_monthly is not None:
            data['keep-monthly'] = keep_monthly
        if keep_yearly is not None:
            data['keep-yearly'] = keep_yearly
        if backup_type:
            data['backup-type'] = backup_type
        if backup_id:
            data['backup-id'] = backup_id
        if dry_run:
            data['dry-run'] = True
        return self.api_post(f'/admin/datastore/{store}/prune-datastore', data=data)
    
    def delete_snapshot(self, store: str, backup_type: str, backup_id: str, 
                        backup_time: str, ns: str = None) -> dict:
        """Delete a specific snapshot"""
        params = {
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': backup_time,
        }
        if ns:
            params['ns'] = ns
        return self.api_delete(f'/admin/datastore/{store}/snapshots', params=params)
    
    # ── Tasks ──
    
    def get_tasks(self, limit: int = 50, running: bool = None, typefilter: str = None,
                  since: int = None) -> dict:
        """List tasks on the PBS server"""
        params = {'limit': limit}
        if running is not None:
            params['running'] = 1 if running else 0
        if typefilter:
            params['typefilter'] = typefilter
        if since:
            params['since'] = since
        return self.api_get('/nodes/localhost/tasks', params=params)
    
    def get_task_status(self, upid: str) -> dict:
        """Get status of a specific task"""
        return self.api_get(f'/nodes/localhost/tasks/{upid}/status')
    
    def get_task_log(self, upid: str) -> dict:
        """Get log output of a task"""
        return self.api_get(f'/nodes/localhost/tasks/{upid}/log')
    
    # ── Jobs ──
    
    def get_sync_jobs(self) -> dict:
        """List configured sync jobs"""
        return self.api_get('/config/sync')
    
    def get_verify_jobs(self) -> dict:
        """List configured verify jobs"""
        return self.api_get('/config/verify')
    
    def get_prune_jobs(self) -> dict:
        """List configured prune jobs"""
        return self.api_get('/config/prune')
    
    def run_sync_job(self, job_id: str) -> dict:
        """Manually trigger a sync job"""
        return self.api_post(f'/admin/sync/{job_id}/run')
    
    def run_verify_job(self, job_id: str) -> dict:
        """Manually trigger a verify job"""
        return self.api_post(f'/admin/verify/{job_id}/run')
    
    def run_prune_job(self, job_id: str) -> dict:
        """Manually trigger a prune job"""
        return self.api_post(f'/admin/prune/{job_id}/run')
    
    # ── Disks (for dashboard) ──
    
    def get_disks(self) -> dict:
        """List disks on the PBS server"""
        return self.api_get('/nodes/localhost/disks/list')
    
    def get_remotes(self) -> dict:
        """List configured remotes (for sync jobs)"""
        return self.api_get('/config/remote')
    
    def get_subscription(self) -> dict:
        """Get subscription status"""
        return self.api_get('/nodes/localhost/subscription')
    
    def get_datastore_rrd(self, store: str, timeframe: str = 'hour', cf: str = 'AVERAGE') -> dict:
        """Get RRD performance data for a datastore"""
        return self.api_get(f'/admin/datastore/{store}/rrd', params={'timeframe': timeframe, 'cf': cf})
    
    # ── Snapshot & Group Notes ──
    
    def get_snapshot_notes(self, store: str, backup_type: str, backup_id: str, backup_time: int) -> dict:
        """Get notes for a specific snapshot"""
        return self.api_get(f'/admin/datastore/{store}/notes', params={
            'backup-type': backup_type, 'backup-id': backup_id, 'backup-time': backup_time
        })
    
    def set_snapshot_notes(self, store: str, backup_type: str, backup_id: str, backup_time: int, notes: str) -> dict:
        """Set notes for a specific snapshot"""
        return self.api_put(f'/admin/datastore/{store}/notes', data={
            'backup-type': backup_type, 'backup-id': backup_id, 'backup-time': backup_time, 'notes': notes
        })
    
    def get_group_notes(self, store: str, backup_type: str, backup_id: str) -> dict:
        """Get notes for a backup group"""
        return self.api_get(f'/admin/datastore/{store}/group-notes', params={
            'backup-type': backup_type, 'backup-id': backup_id
        })
    
    def set_group_notes(self, store: str, backup_type: str, backup_id: str, notes: str) -> dict:
        """Set notes for a backup group"""
        return self.api_put(f'/admin/datastore/{store}/group-notes', data={
            'backup-type': backup_type, 'backup-id': backup_id, 'notes': notes
        })
    
    # ── Snapshot Protection ──
    
    def set_snapshot_protected(self, store: str, backup_type: str, backup_id: str, backup_time: int, protected: bool) -> dict:
        """Set protected flag on a snapshot"""
        return self.api_put(f'/admin/datastore/{store}/protected', data={
            'backup-type': backup_type, 'backup-id': backup_id, 'backup-time': backup_time, 'protected': protected
        })
    
    # ── Traffic Control ──
    
    def get_traffic_control(self) -> dict:
        """Get traffic control / bandwidth limit configuration"""
        return self.api_get('/config/traffic-control')
    
    # ── Syslog ──
    
    def get_syslog(self, limit: int = 50, since: str = None) -> dict:
        """Get system log entries"""
        params = {'limit': limit}
        if since:
            params['since'] = since
        return self.api_get('/nodes/localhost/syslog', params=params)
    
    # ── Node RRD (server-level performance) ──
    
    def get_node_rrd(self, timeframe: str = 'hour', cf: str = 'AVERAGE') -> dict:
        """Get RRD performance data for the PBS node"""
        return self.api_get('/nodes/localhost/rrd', params={'timeframe': timeframe, 'cf': cf})
    
    # ── Notifications ──
    
    def get_notification_targets(self) -> dict:
        """Get notification endpoint configuration (sendmail, gotify, smtp, webhook)"""
        return self.api_get('/config/notifications/endpoints')
    
    def get_notification_matchers(self) -> dict:
        """Get notification matcher rules"""
        return self.api_get('/config/notifications/matchers')
    
    # ── Catalog / File-Level Restore ──
    
    def browse_catalog(self, store: str, backup_type: str, backup_id: str, backup_time: int, filepath: str = '/') -> dict:
        """Browse file catalog of a pxar snapshot - list directory contents"""
        return self.api_get(f'/admin/datastore/{store}/catalog', params={
            'backup-type': backup_type, 'backup-id': backup_id,
            'backup-time': backup_time, 'filepath': filepath
        })
    
    def download_file_from_snapshot(self, store: str, backup_type: str, backup_id: str, backup_time: int, filepath: str):
        """Download a single file from a pxar archive in a snapshot.
        Returns (response_object) for streaming to client."""
        resp = self.api_get_raw(f'/admin/datastore/{store}/pxar-file-download', params={
            'backup-type': backup_type, 'backup-id': backup_id,
            'backup-time': backup_time, 'filepath': filepath
        })
        return resp
    
    # ── Job CRUD ── NS: Feb 2026 ──
    
    def create_sync_job(self, job_id: str, store: str, remote: str, remote_store: str, 
                        schedule: str = None, remove_vanished: bool = None, comment: str = None,
                        ns: str = None, max_depth: int = None) -> dict:
        """Create a new sync job"""
        data = {'id': job_id, 'store': store, 'remote': remote, 'remote-store': remote_store}
        if schedule: data['schedule'] = schedule
        if remove_vanished is not None: data['remove-vanished'] = remove_vanished
        if comment: data['comment'] = comment
        if ns: data['ns'] = ns
        if max_depth is not None: data['max-depth'] = max_depth
        return self.api_post('/config/sync', data=data)
    
    def update_sync_job(self, job_id: str, **kwargs) -> dict:
        """Update sync job config"""
        data = {}
        key_map = {'schedule': 'schedule', 'remove_vanished': 'remove-vanished', 
                   'comment': 'comment', 'ns': 'ns', 'max_depth': 'max-depth'}
        for k, api_k in key_map.items():
            if k in kwargs and kwargs[k] is not None:
                data[api_k] = kwargs[k]
        if 'delete' in kwargs: data['delete'] = ','.join(kwargs['delete'])
        return self.api_put(f'/config/sync/{job_id}', data=data)
    
    def delete_sync_job(self, job_id: str) -> dict:
        """Delete a sync job"""
        return self.api_delete(f'/config/sync/{job_id}')
    
    def create_verify_job(self, job_id: str, store: str, schedule: str = None,
                          ignore_verified: bool = None, outdated_after: str = None,
                          comment: str = None, ns: str = None) -> dict:
        """Create a new verify job"""
        data = {'id': job_id, 'store': store}
        if schedule: data['schedule'] = schedule
        if ignore_verified is not None: data['ignore-verified'] = ignore_verified
        if outdated_after: data['outdated-after'] = outdated_after
        if comment: data['comment'] = comment
        if ns: data['ns'] = ns
        return self.api_post('/config/verify', data=data)
    
    def update_verify_job(self, job_id: str, **kwargs) -> dict:
        """Update verify job config"""
        data = {}
        key_map = {'schedule': 'schedule', 'ignore_verified': 'ignore-verified',
                   'outdated_after': 'outdated-after', 'comment': 'comment', 'ns': 'ns'}
        for k, api_k in key_map.items():
            if k in kwargs and kwargs[k] is not None:
                data[api_k] = kwargs[k]
        if 'delete' in kwargs: data['delete'] = ','.join(kwargs['delete'])
        return self.api_put(f'/config/verify/{job_id}', data=data)
    
    def delete_verify_job(self, job_id: str) -> dict:
        """Delete a verify job"""
        return self.api_delete(f'/config/verify/{job_id}')
    
    def create_prune_job(self, job_id: str, store: str, schedule: str = None,
                         keep_last: int = None, keep_daily: int = None, keep_weekly: int = None,
                         keep_monthly: int = None, keep_yearly: int = None,
                         comment: str = None, ns: str = None) -> dict:
        """Create a new prune job"""
        data = {'id': job_id, 'store': store}
        if schedule: data['schedule'] = schedule
        for k in ['keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly', 'keep_yearly']:
            v = locals().get(k)
            if v is not None: data[k.replace('_', '-')] = v
        if comment: data['comment'] = comment
        if ns: data['ns'] = ns
        return self.api_post('/config/prune', data=data)
    
    def update_prune_job(self, job_id: str, **kwargs) -> dict:
        """Update prune job config"""
        data = {}
        key_map = {'schedule': 'schedule', 'comment': 'comment', 'ns': 'ns',
                   'keep_last': 'keep-last', 'keep_daily': 'keep-daily', 'keep_weekly': 'keep-weekly',
                   'keep_monthly': 'keep-monthly', 'keep_yearly': 'keep-yearly'}
        for k, api_k in key_map.items():
            if k in kwargs and kwargs[k] is not None:
                data[api_k] = kwargs[k]
        if 'delete' in kwargs: data['delete'] = ','.join(kwargs['delete'])
        return self.api_put(f'/config/prune/{job_id}', data=data)
    
    def delete_prune_job(self, job_id: str) -> dict:
        """Delete a prune job"""
        return self.api_delete(f'/config/prune/{job_id}')
    
    # ── Task Management ──
    
    def stop_task(self, upid: str) -> dict:
        """Stop/abort a running task"""
        return self.api_delete(f'/nodes/localhost/tasks/{upid}')
    
    # ── Notification CRUD ──
    # MK 2026-05-31 — defense-in-depth: previous code unpacked `**kwargs`
    # straight into the PBS API call body. An admin with notification-manage
    # perm could inject arbitrary field names which PBS might silently store
    # in the config file. PBS / PVE field-naming convention is
    # `^[a-z][a-z0-9-]{0,30}$`, values are scalars or None — anything else is
    # treated as bogus and dropped. The traffic_control methods below already
    # had explicit whitelisting; this brings notifications inline.
    @staticmethod
    def _sanitize_pbs_kwargs(kwargs: dict) -> dict:
        import re as _re
        _key_re = _re.compile(r'^[a-z][a-z0-9-]{0,30}$')
        clean = {}
        for k, v in (kwargs or {}).items():
            if not isinstance(k, str) or not _key_re.match(k):
                continue
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                # PBS arrays-as-CSV — only accept lists of scalars
                if all(isinstance(x, (str, int, bool)) for x in v):
                    clean[k] = v
                continue
            if isinstance(v, (str, int, bool)):
                clean[k] = v
        return clean

    def create_notification_target(self, target_type: str, name: str, **kwargs) -> dict:
        """Create notification endpoint (sendmail, gotify, smtp, webhook)"""
        data = {'name': name, **self._sanitize_pbs_kwargs(kwargs)}
        return self.api_post(f'/config/notifications/endpoints/{target_type}', data=data)

    def update_notification_target(self, target_type: str, name: str, **kwargs) -> dict:
        """Update notification endpoint"""
        return self.api_put(f'/config/notifications/endpoints/{target_type}/{name}',
                            data=self._sanitize_pbs_kwargs(kwargs))

    def delete_notification_target(self, target_type: str, name: str) -> dict:
        """Delete notification endpoint"""
        return self.api_delete(f'/config/notifications/endpoints/{target_type}/{name}')

    def create_notification_matcher(self, name: str, **kwargs) -> dict:
        """Create notification matcher rule"""
        data = {'name': name, **self._sanitize_pbs_kwargs(kwargs)}
        return self.api_post('/config/notifications/matchers', data=data)

    def update_notification_matcher(self, name: str, **kwargs) -> dict:
        """Update notification matcher"""
        return self.api_put(f'/config/notifications/matchers/{name}',
                            data=self._sanitize_pbs_kwargs(kwargs))
    
    def delete_notification_matcher(self, name: str) -> dict:
        """Delete notification matcher"""
        return self.api_delete(f'/config/notifications/matchers/{name}')
    
    # ── Traffic Control CRUD ──
    
    def create_traffic_control(self, name: str, rate_in: str = None, rate_out: str = None,
                               burst_in: str = None, burst_out: str = None,
                               network: str = None, timeframe: str = None, comment: str = None) -> dict:
        """Create traffic control rule"""
        data = {'name': name}
        if rate_in: data['rate-in'] = rate_in
        if rate_out: data['rate-out'] = rate_out
        if burst_in: data['burst-in'] = burst_in
        if burst_out: data['burst-out'] = burst_out
        if network: data['network'] = network
        if timeframe: data['timeframe'] = timeframe
        if comment: data['comment'] = comment
        return self.api_post('/config/traffic-control', data=data)
    
    def update_traffic_control(self, name: str, **kwargs) -> dict:
        """Update traffic control rule"""
        data = {}
        for k in ['rate_in', 'rate_out', 'burst_in', 'burst_out', 'network', 'timeframe', 'comment']:
            if k in kwargs and kwargs[k] is not None:
                data[k.replace('_', '-')] = kwargs[k]
        if 'delete' in kwargs: data['delete'] = ','.join(kwargs['delete'])
        return self.api_put(f'/config/traffic-control/{name}', data=data)
    
    def delete_traffic_control(self, name: str) -> dict:
        """Delete traffic control rule"""
        return self.api_delete(f'/config/traffic-control/{name}')
    
    # ── Disk SMART ──
    
    def get_disk_smart(self, disk: str) -> dict:
        """Get SMART data for a specific disk"""
        return self.api_get(f'/nodes/localhost/disks/smart', params={'disk': disk})
    
    # ── Subscription ──
    
    def set_subscription(self, key: str) -> dict:
        """Set/update subscription key"""
        return self.api_post('/nodes/localhost/subscription', data={'key': key})
    
    # ── Network/DNS/Time ──
    
    def get_network(self) -> dict:
        """Get network interface configuration"""
        return self.api_get('/nodes/localhost/network')
    
    def get_dns(self) -> dict:
        """Get DNS configuration"""
        return self.api_get('/nodes/localhost/dns')
    
    def get_time(self) -> dict:
        """Get timezone configuration"""
        return self.api_get('/nodes/localhost/time')
    
        # ── Datastore CRUD ──
    
    def create_datastore(self, name: str, path: str, comment: str = '',
                         gc_schedule: str = None, keep_last: int = None,
                         keep_daily: int = None, keep_weekly: int = None,
                         keep_monthly: int = None, keep_yearly: int = None,
                         verify_new: bool = None, notify: str = None,
                         notify_user: str = None) -> dict:
        """create datastore on PBS server"""
        data = {
            'name': name,
            'path': path,
        }
        if comment:
            data['comment'] = comment
        if gc_schedule is not None:
            data['gc-schedule'] = gc_schedule
        if keep_last is not None:
            data['keep-last'] = keep_last
        if keep_daily is not None:
            data['keep-daily'] = keep_daily
        if keep_weekly is not None:
            data['keep-weekly'] = keep_weekly
        if keep_monthly is not None:
            data['keep-monthly'] = keep_monthly
        if keep_yearly is not None:
            data['keep-yearly'] = keep_yearly
        if verify_new is not None:
            data['verify-new'] = verify_new
        if notify is not None:
            data['notify'] = notify
        if notify_user is not None:
            data['notify-user'] = notify_user
        return self.api_post('/config/datastore', data=data)
    
    def update_datastore(self, store: str, comment: str = None,
                         gc_schedule: str = None, keep_last: int = None,
                         keep_daily: int = None, keep_weekly: int = None,
                         keep_monthly: int = None, keep_yearly: int = None,
                         verify_new: bool = None, notify: str = None,
                         notify_user: str = None,
                         delete: list = None) -> dict:
        """update datastore config (retention, gc schedule, notifications, etc.)"""
        data = {}
        if comment is not None:
            data['comment'] = comment
        if gc_schedule is not None:
            data['gc-schedule'] = gc_schedule
        if keep_last is not None:
            data['keep-last'] = keep_last
        if keep_daily is not None:
            data['keep-daily'] = keep_daily
        if keep_weekly is not None:
            data['keep-weekly'] = keep_weekly
        if keep_monthly is not None:
            data['keep-monthly'] = keep_monthly
        if keep_yearly is not None:
            data['keep-yearly'] = keep_yearly
        if verify_new is not None:
            data['verify-new'] = verify_new
        if notify is not None:
            data['notify'] = notify
        if notify_user is not None:
            data['notify-user'] = notify_user
        if delete:
            data['delete'] = ','.join(delete)
        if not data:
            return {'error': 'No changes specified'}
        return self.api_put(f'/config/datastore/{store}', data=data)
    
    def delete_datastore(self, store: str, keep_data: bool = True) -> dict:
        """remove datastore from PBS config. NS: keep_data=True by default so we only remove config, not actual backup data"""
        params = {}
        if not keep_data:
            params['destroy-data'] = True
        return self.api_delete(f'/config/datastore/{store}', params=params)
    
    def get_datastore_config(self, store: str) -> dict:
        """Get the configuration (not status) of a specific datastore
        
        Returns retention settings, GC schedule, notifications, etc.
        This is separate from get_datastore_status() which returns usage/health.
        """
        return self.api_get(f'/config/datastore/{store}')
    
    # ── Serialization ──
    
    def to_dict(self) -> dict:
        """Convert to dict for API response (no secrets)"""
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'port': self.port,
            'user': self.user,
            'api_token_id': self.api_token_id,
            'fingerprint': self.fingerprint,
            'ssl_verify': self.ssl_verify,
            'enabled': self.enabled,
            'connected': self.connected,
            'last_error': self.last_error,
            'linked_clusters': self.linked_clusters,
            'notes': self.notes,
            'using_api_token': self._using_api_token,
            # NS Apr 2026: SSH config — secret key is masked so UI can show "configured" state
            'ssh_user': self.ssh_user,
            'ssh_port': self.ssh_port,
            'has_ssh_key': bool(self.ssh_key),
        }


def load_pbs_servers():
    """Load all PBS server configs from DB and create managers"""
    global pbs_managers
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT * FROM pbs_servers WHERE enabled = 1")
        rows = cursor.fetchall()
        
        for row in rows:
            row_dict = dict(row)
            pbs_id = row_dict['id']
            
            # Decrypt credentials
            password = ''
            if row_dict.get('pass_encrypted'):
                try:
                    password = db._decrypt(row_dict['pass_encrypted'])
                except Exception:
                    password = ''
            
            api_token_secret = ''
            if row_dict.get('api_token_secret_encrypted'):
                try:
                    api_token_secret = db._decrypt(row_dict['api_token_secret_encrypted'])
                except Exception:
                    api_token_secret = ''
            
            ssh_key = ''
            if row_dict.get('ssh_key_encrypted'):
                try:
                    ssh_key = db._decrypt(row_dict['ssh_key_encrypted'])
                except Exception:
                    ssh_key = ''

            config = {
                'name': row_dict.get('name', 'PBS'),
                'host': row_dict.get('host', ''),
                'port': row_dict.get('port', 8007),
                'user': row_dict.get('user', 'root@pam'),
                'password': password,
                'api_token_id': row_dict.get('api_token_id', ''),
                'api_token_secret': api_token_secret,
                'fingerprint': row_dict.get('fingerprint', ''),
                'ssl_verify': bool(row_dict.get('ssl_verify', 0)),
                'enabled': bool(row_dict.get('enabled', 1)),
                'linked_clusters': json.loads(row_dict.get('linked_clusters', '[]')),
                'notes': row_dict.get('notes', ''),
                'ssh_user': row_dict.get('ssh_user', '') or '',
                'ssh_port': row_dict.get('ssh_port', 22) or 22,
                'ssh_key': ssh_key,
            }
            
            try:
                mgr = PBSManager(pbs_id, config)
                if config['enabled']:
                    mgr.connect()
                pbs_managers[pbs_id] = mgr
            except ValueError as e:
                logging.warning(f"[PBS] Skipping PBS server {pbs_id} ({config.get('name', 'unknown')}): Invalid or disallowed host")
                continue
            
        logging.info(f"[PBS] Loaded {len(rows)} PBS servers ({sum(1 for m in pbs_managers.values() if m.connected)} connected)")
    except Exception as e:
        logging.warning(f"[PBS] Failed to load PBS servers: {e}")


def save_pbs_server(pbs_id: str, config: dict):
    """Save a PBS server config to DB"""
    db = get_db()
    cursor = db.conn.cursor()
    
    # Encrypt credentials
    pass_encrypted = ''
    if config.get('password') and config['password'] != '********':
        pass_encrypted = db._encrypt(config['password'])

    api_token_secret_encrypted = ''
    if config.get('api_token_secret') and config['api_token_secret'] != '********':
        api_token_secret_encrypted = db._encrypt(config['api_token_secret'])

    # NS Apr 2026: SSH key for apt-upgrade runner
    ssh_key_encrypted = ''
    if config.get('ssh_key') and config['ssh_key'] != '********':
        ssh_key_encrypted = db._encrypt(config['ssh_key'])

    # fetch old values once to preserve encrypted fields when blank is submitted
    existing = cursor.execute(
        "SELECT pass_encrypted, api_token_secret_encrypted, ssh_key_encrypted FROM pbs_servers WHERE id = ?",
        (pbs_id,)
    ).fetchone()
    old_pass = existing[0] if existing else ''
    old_token = existing[1] if existing else ''
    old_sshkey = existing[2] if existing and len(existing) > 2 else ''

    cursor.execute('''
        INSERT OR REPLACE INTO pbs_servers
        (id, name, host, port, user, pass_encrypted, api_token_id, api_token_secret_encrypted,
         fingerprint, ssl_verify, enabled, linked_clusters, notes,
         ssh_user, ssh_port, ssh_key_encrypted,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?,
                COALESCE((SELECT created_at FROM pbs_servers WHERE id = ?), ?), ?)
    ''', (
        pbs_id, config.get('name', 'PBS'), config.get('host', ''), int(config.get('port', 8007)),
        config.get('user', 'root@pam'),
        pass_encrypted or old_pass,
        config.get('api_token_id', ''),
        api_token_secret_encrypted or old_token,
        config.get('fingerprint', ''), int(config.get('ssl_verify', False)),
        int(config.get('enabled', True)), json.dumps(config.get('linked_clusters', [])),
        config.get('notes', ''),
        config.get('ssh_user', '') or '',
        int(config.get('ssh_port', 22) or 22),
        ssh_key_encrypted or old_sshkey,
        pbs_id, datetime.now().isoformat(), datetime.now().isoformat(),
    ))
    db.conn.commit()


