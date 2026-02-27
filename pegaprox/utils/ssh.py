# -*- coding: utf-8 -*-
"""
PegaProx SSH Utilities - Layer 2
SSH connection management, rate limiting, and execution.
"""

import os
import time
import logging
import threading
import socket

from pegaprox.constants import SSH_MAX_CONCURRENT
from pegaprox.globals import (
    _ssh_active_connections, _ssh_connection_lock,
    _auth_action_attempts, _auth_action_lock,
    cluster_managers,
)

def get_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None

def get_ssh_connection_stats():
    """Get current SSH connection statistics"""
    with _ssh_connection_lock:
        return {
            'max_concurrent': SSH_MAX_CONCURRENT,
            'active_normal': _ssh_active_connections['normal'],
            'active_ha': _ssh_active_connections['ha'],
            'total_active': _ssh_active_connections['normal'] + _ssh_active_connections['ha']
        }

def _ssh_track_connection(conn_type: str, delta: int):
    """Track SSH connection count"""
    with _ssh_connection_lock:
        _ssh_active_connections[conn_type] = max(0, _ssh_active_connections[conn_type] + delta)

# NS: Feb 2026 - Rate limiter for authenticated security actions
# Prevents brute-force of TOTP codes, passwords via 2FA disable/password change
# These endpoints require a session, but a stolen session could be used to brute-force
_auth_action_attempts = {}  # key -> [timestamps]
_auth_action_lock = threading.Lock()

def check_auth_action_rate_limit(key: str, max_attempts: int = 5, window: int = 300) -> bool:
    """Simple sliding window rate limiter for auth actions (2FA verify, pwd change, etc.)
    MK: 5 attempts per 5 min by default, should be enough for typos but stops brute force
    """
    now = time.time()
    with _auth_action_lock:
        if key not in _auth_action_attempts:
            _auth_action_attempts[key] = []
        attempts = [t for t in _auth_action_attempts[key] if now - t < window]
        if len(attempts) >= max_attempts:
            return False
        attempts.append(now)
        _auth_action_attempts[key] = attempts
        return True

# Global sessions store
# MK: this is in-memory, will be lost on restart
# TODO: persist to redis or file?
active_sessions = {}  # session_id -> {user, created_at, last_activity, role}

# NS: Track PegaProx user who initiated each task (UPID -> username)
# This allows us to show who triggered a task in the UI, not just the Proxmox user (root@pam)
# Now persisted to database so it survives restarts and is visible to all users
task_pegaprox_users_cache = {}  # In-memory cache for fast lookups
task_pegaprox_users_lock = threading.Lock()
TASK_USER_CACHE_TTL = 86400  # Keep for 24 hours (in DB, will be cleaned on startup)

def _ssh_exec(host, user, password, cmd, timeout=30):
    """Execute command on remote host via SSH.
    Handles ESXi which only allows 'keyboard-interactive' and 'publickey'.
    
    ESXi SSH quirks:
    - Only allows keyboard-interactive and publickey auth (NOT password)
    - Older ESXi (6.x/7.x) uses legacy kex/key algorithms that modern
      paramiko disables by default (diffie-hellman-group14-sha1, ssh-rsa)
    """
    last_err = ''
    errors = []
    
    def _configure_transport_algorithms(t):
        """Add ESXi-compatible legacy algorithms to paramiko Transport."""
        try:
            sec = t.get_security_options()
            
            esxi_kex = (
                'diffie-hellman-group14-sha256',
                'diffie-hellman-group14-sha1',
                'diffie-hellman-group1-sha1',
                'ecdh-sha2-nistp256',
                'ecdh-sha2-nistp384',
                'ecdh-sha2-nistp521',
            )
            existing_kex = tuple(sec.kex)
            merged_kex = existing_kex + tuple(k for k in esxi_kex if k not in existing_kex)
            try:
                sec.kex = merged_kex
            except ValueError:
                for kex in esxi_kex:
                    try:
                        sec.kex = existing_kex + (kex,)
                        existing_kex = tuple(sec.kex)
                    except ValueError:
                        pass
            
            esxi_keys = ('ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519',
                         'rsa-sha2-256', 'rsa-sha2-512')
            existing_keys = tuple(sec.key_types)
            merged_keys = existing_keys + tuple(k for k in esxi_keys if k not in existing_keys)
            try:
                sec.key_types = merged_keys
            except ValueError:
                for kt in esxi_keys:
                    try:
                        sec.key_types = existing_keys + (kt,)
                        existing_keys = tuple(sec.key_types)
                    except ValueError:
                        pass
        except Exception:
            pass  # If security options API changed, try with defaults
    
    # Try paramiko first
    try:
        import paramiko
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connected = False
        transport = None
        
        # Method 1: keyboard-interactive via Transport (what ESXi wants)
        try:
            transport = paramiko.Transport((host, 22))
            _configure_transport_algorithms(transport)
            transport.connect()
            
            def _ki_handler(title, instructions, prompt_list):
                return [password] * len(prompt_list)
            
            transport.auth_interactive(user, _ki_handler)
            
            if transport.is_authenticated():
                client._transport = transport
                connected = True
        except Exception as e:
            errors.append(f'M1(ki-transport): {e}')
            last_err = str(e)
            if transport:
                try: transport.close()
                except: pass
            transport = None
        
        # Method 2: keyboard-interactive via second Transport
        if not connected:
            try:
                client2 = paramiko.SSHClient()
                client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                transport2 = paramiko.Transport((host, 22))
                _configure_transport_algorithms(transport2)
                transport2.connect()
                
                def _ki_handler2(title, instructions, prompt_list):
                    return [password] * len(prompt_list)
                
                try:
                    transport2.auth_interactive(user, _ki_handler2)
                except Exception:
                    if not transport2.is_authenticated():
                        transport2.auth_password(user, password)
                
                if transport2.is_authenticated():
                    client2._transport = transport2
                    client = client2
                    connected = True
                else:
                    transport2.close()
            except Exception as e:
                errors.append(f'M2(ki-client): {e}')
                last_err = str(e)
                try: transport2.close()
                except: pass
        
        # Method 3: Standard password auth (for non-ESXi hosts)
        if not connected:
            try:
                client3 = paramiko.SSHClient()
                client3.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client3.connect(host, username=user, password=password, timeout=timeout,
                               allow_agent=False, look_for_keys=False)
                client = client3
                connected = True
            except Exception as e:
                errors.append(f'M3(password): {e}')
                last_err = str(e)
        
        if not connected:
            err_detail = '; '.join(errors)
            raise Exception(f'Paramiko auth failed ({len(errors)} methods): {err_detail}')
        
        # Execute command
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            rc = stdout.channel.recv_exit_status()
            client.close()
            return rc, out, err
        except Exception as e:
            try: client.close()
            except: pass
            raise Exception(f'Paramiko exec failed: {e}')
    
    except Exception as paramiko_err:
        last_err = str(paramiko_err)
    
    # Fallback: sshpass + ssh subprocess (handles keyboard-interactive via PreferredAuthentications)
    try:
        import subprocess
        env = os.environ.copy()
        env['SSHPASS'] = password
        result = subprocess.run(
            ['sshpass', '-e', 'ssh',
             '-o', 'StrictHostKeyChecking=no',
             '-o', 'UserKnownHostsFile=/dev/null',
             '-o', 'LogLevel=ERROR',
             '-o', 'PreferredAuthentications=keyboard-interactive,password',
             '-o', 'HostKeyAlgorithms=+ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256',
             '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519',
             '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256',
             f'{user}@{host}', cmd],
            capture_output=True, text=True, timeout=timeout, env=env
        )
        if result.returncode == 0:
            return result.returncode, result.stdout, result.stderr
        # sshpass also failed
        return result.returncode, result.stdout, result.stderr or last_err
    except Exception as sub_err:
        return 1, '', f'All SSH methods failed: {last_err}; subprocess: {sub_err}'


_node_ip_cache = {}  # (cluster_id, node) -> (ip, timestamp)

def _pve_node_exec(pve_mgr, node, cmd, timeout=600):
    """Execute a command on a Proxmox node via the Proxmox API.
    Uses POST /nodes/{node}/execute or falls back to SSH."""
    # Method 1: Try Proxmox API exec (PVE 7.4+)
    try:
        resp = pve_mgr._api_post(
            f"https://{pve_mgr.host}:8006/api2/json/nodes/{node}/execute",
            data={'commands': cmd}
        )
        if resp.status_code == 200:
            return 0, resp.json().get('data', ''), ''
    except Exception:
        pass
    
    # Method 2: SSH directly to the node
    # Resolve node IP: check cache, then API, then hostname, then cluster host
    node_host = None
    cache_key = (pve_mgr.id, node)
    
    # Check cache first (5 min TTL)
    if cache_key in _node_ip_cache:
        cached_ip, cached_time = _node_ip_cache[cache_key]
        if time.time() - cached_time < 300:
            node_host = cached_ip
    
    if not node_host:
        # Try to get node IP from Proxmox network config
        try:
            net_resp = pve_mgr._api_get(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{node}/network")
            if net_resp.status_code == 200:
                for iface in net_resp.json().get('data', []):
                    addr = iface.get('address', iface.get('cidr', ''))
                    if addr and iface.get('active') and iface.get('iface', '') != 'lo':
                        ip = addr.split('/')[0]
                        if ip and not ip.startswith('127.'):
                            node_host = ip
                            break
        except:
            pass
    
    if not node_host:
        # Try DNS resolution of node hostname
        try:
            import socket
            node_host = socket.gethostbyname(node)
        except:
            pass
    
    if not node_host:
        # Try corosync config for node IP
        try:
            corosync_resp = pve_mgr._api_get(
                f"https://{pve_mgr.host}:8006/api2/json/cluster/config/nodes")
            if corosync_resp.status_code == 200:
                for n in corosync_resp.json().get('data', []):
                    if n.get('name') == node or n.get('node') == node:
                        node_host = n.get('ip', n.get('ring0_addr', ''))
                        break
        except:
            pass
    
    # Last resort: cluster host
    if not node_host:
        node_host = pve_mgr.host
    
    # Cache the resolved IP
    _node_ip_cache[cache_key] = (node_host, time.time())
    
    try:
        rc, out, err = _ssh_exec(node_host, 'root', pve_mgr.config.pass_, cmd, timeout=timeout)
        return rc, out, err
    except Exception as e:
        return 1, '', str(e)


