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
from pegaprox.utils.ssh_security import apply_host_key_policy, persist_host_keys, verify_transport_host_key
from pegaprox.globals import (
    _ssh_active_connections, _ssh_connection_lock,
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
#
# MK Sep 2026 - this was the last of the longhand limiters and it was the one that
# mattered most: /api/webauthn/auth/begin calls it with the raw client IP and that route
# takes no session, so an anonymous caller rotating source addresses grew the map for
# free. Over IPv6 that is a /64 worth of keys and nothing ever removed one. Same shape
# the SlidingWindow module was written for, so use it here too rather than keep a ninth
# copy. One window per (max_attempts, window) pair - the call sites use three fixed
# pairs, so that registry is bounded by the code, not by anything a caller sends.
_auth_action_windows = {}
_auth_action_lock = threading.Lock()
# The registry is keyed by the budget the CALLER asks for, and every entry owns a window
# that can hold 4096 keys. Today all four call sites pass literals - (5,300), (3,120),
# (20,300) - so it holds three, and the day somebody wires a request-derived budget in
# here the leak comes back bigger than the one this replaced. Bound it the same way
# SlidingWindow bounds its own keys rather than trusting the call sites to stay literal.
_AUTH_ACTION_MAX_BUCKETS = 8


def check_auth_action_rate_limit(key: str, max_attempts: int = 5, window: int = 300) -> bool:
    """Sliding window rate limiter for auth actions (2FA verify, pwd change, webauthn).
    MK: 5 attempts per 5 min by default, should be enough for typos but stops brute force.
    Keys are capped, so the limiter cannot itself be used to exhaust us.
    """
    from pegaprox.utils.ratelimit import SlidingWindow
    bucket = (int(max_attempts), int(window))
    with _auth_action_lock:
        win = _auth_action_windows.get(bucket)
        if win is None:
            if len(_auth_action_windows) >= _AUTH_ACTION_MAX_BUCKETS:
                # More distinct budgets than the code has call sites means somebody is
                # passing them in from a request. Drop the least recently created one;
                # the budgets themselves are not secret and a re-created window simply
                # starts counting again.
                oldest = next(iter(_auth_action_windows))
                _auth_action_windows.pop(oldest, None)
                logging.warning(
                    '[RATELIMIT] auth-action budgets exceeded %d distinct pairs - '
                    'evicted %s. A caller is choosing the budget; it should be a literal.',
                    _AUTH_ACTION_MAX_BUCKETS, oldest)
            win = SlidingWindow(limit=max_attempts, window=window, max_keys=4096,
                                name=f'auth-action-{max_attempts}/{window}')
            _auth_action_windows[bucket] = win
    return win.allow(key)

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

# MK Sep 2026 - a managed node answers over a channel we do not get to bound. `read()`
# on a paramiko ChannelFile reads to EOF, so one runaway command, one enormous log, or
# one node somebody else controls takes the hub's memory with it - and this copies on a
# greenlet that yields to nobody while it runs. 8 MB is far past anything a legitimate
# command here produces (the biggest are apt logs, a few hundred KB).
_SSH_OUTPUT_CAP = max(1, int(os.environ.get('PEGAPROX_SSH_OUTPUT_MB', '8') or 8)) * 1024 * 1024
_SSH_DRAIN_FACTOR = 10          # keep draining past the cap so the far end is not wedged


def read_capped(fh, limit=None):
    """Read a paramiko channel file into a str, bounded.

    Past the cap the content is dropped but the channel keeps being drained, so the
    remote is not left blocked writing into a full pipe and recv_exit_status() still
    comes back. At limit*_SSH_DRAIN_FACTOR the command is pathological rather than
    chatty and we stop; the channel timeout bounds the wall clock either way.
    Returns the text with a marker appended when anything was dropped.
    """
    limit = _SSH_OUTPUT_CAP if limit is None else limit
    chunks, kept, seen = [], 0, 0
    hard = limit * _SSH_DRAIN_FACTOR
    while True:
        try:
            block = fh.read(65536)
        except Exception:
            break
        if not block:
            break
        seen += len(block)
        if kept < limit:
            take = block[:limit - kept]
            chunks.append(take)
            kept += len(take)
        if seen >= hard:
            break
    out = b''.join(chunks).decode('utf-8', errors='replace')
    if seen > kept:
        out += f"\n[... output truncated at {kept} of {seen}+ bytes ...]"
    return out


def _ssh_exec(host, user, password, cmd, timeout=30, use_controlmaster=False,
              connect_timeout=8):
    """Execute command on remote host via SSH.
    Handles ESXi which only allows 'keyboard-interactive' and 'publickey'.

    ESXi SSH quirks:
    - Only allows keyboard-interactive and publickey auth (NOT password)
    - Older ESXi (6.x/7.x) uses legacy kex/key algorithms that modern
      paramiko disables by default (diffie-hellman-group14-sha1, ssh-rsa)

    NS Apr 2026 (Phase 2):
    - use_controlmaster=True enables OpenSSH ControlMaster sharing on the
      subprocess fallback path. First call to a host opens the master TCP+
      auth, follow-up calls within ControlPersist (300s) reuse it — ~90 %
      latency reduction on wiederholte Calls. If the master can't be opened
      (no /run write, OpenSSH < 5.6, etc.), falls back to fresh connections
      with no error. HA paths in core/manager.py do NOT use this — they
      have their own subprocess+paramiko paths and are intentionally untouched.

    MK May 2026 (dead-node UI hang fix) — split `timeout` into two phases:
    `connect_timeout` (TCP+auth handshake, default 8s — fail fast on dead
    hosts so the UI doesn't hang) and `timeout` (command execution, default
    30s — keeps headroom for long-running ops). paramiko.Transport doesn't
    accept a timeout arg directly, so we pre-create a socket with the
    connect timeout and hand it to Transport. Without this, Transport
    blocks on the kernel TCP default (~75s on Linux without SYN-ACK).
    """
    import socket as _socket
    last_err = ''
    errors = []

    def _make_sock():
        """Pre-create socket with explicit connect_timeout — paramiko.Transport
        won't fail-fast on dead hosts otherwise.  IPv4 + IPv6 aware."""
        try:
            return _socket.create_connection((host, 22), timeout=connect_timeout)
        except Exception:
            return None
    
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
        # MK: Mar 2026 - TOFU: trust on first use, reject if key changes.
        # Single source of truth for the known_hosts path (the real runtime config
        # dir), shared with the system-ssh fallback below so both verify the same file.
        import pegaprox.utils.ssh_security as _sshsec
        _known_hosts = _sshsec._KNOWN_HOSTS
        apply_host_key_policy(client, paramiko)

        connected = False
        transport = None
        
        # Method 1: keyboard-interactive via Transport (what ESXi wants)
        try:
            _sock = _make_sock()
            if _sock is None:
                raise Exception(f'TCP connect to {host}:22 timed out after {connect_timeout}s')
            transport = paramiko.Transport(_sock)
            _configure_transport_algorithms(transport)
            transport.connect()
            # verify the server key BEFORE sending credentials (a manual Transport
            # bypasses the SSHClient host-key policy). Raises on changed/unknown key.
            verify_transport_host_key(transport, host, paramiko)

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
                apply_host_key_policy(client2, paramiko)
                
                _sock2 = _make_sock()
                if _sock2 is None:
                    raise Exception(f'TCP connect to {host}:22 timed out after {connect_timeout}s')
                transport2 = paramiko.Transport(_sock2)
                _configure_transport_algorithms(transport2)
                transport2.connect()
                verify_transport_host_key(transport2, host, paramiko)

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
                apply_host_key_policy(client3, paramiko)
                # NS May 2026 — `timeout` here is paramiko's CONNECT timeout
                # (TCP+auth), not command-exec. Use the dedicated connect
                # phase budget so dead hosts fail in 8s rather than 30s.
                client3.connect(host, username=user, password=password,
                               timeout=connect_timeout,
                               banner_timeout=connect_timeout,
                               auth_timeout=connect_timeout,
                               allow_agent=False, look_for_keys=False)
                client = client3
                connected = True
            except Exception as e:
                errors.append(f'M3(password): {e}')
                last_err = str(e)
        
        if not connected:
            err_detail = '; '.join(errors)
            raise Exception(f'Paramiko auth failed ({len(errors)} methods): {err_detail}')
        
        # MK: Mar 2026 - persist host keys (TOFU model) — reject-on-change next time
        persist_host_keys(client)

        # Execute command
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = read_capped(stdout)
            err = read_capped(stderr)
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
        from pegaprox.utils.ssh_security import strict_host_keys_enabled
        env = os.environ.copy()
        env['SSHPASS'] = password
        # accept-new = TOFU (accept unknown, REJECT a changed key). strict mode
        # upgrades to `yes` (reject unknown too). Keeps the system-ssh fallback's
        # host-key behaviour in lock-step with the paramiko paths.
        _hkc = 'yes' if strict_host_keys_enabled() else 'accept-new'
        ssh_args = ['sshpass', '-e', 'ssh',
             '-o', f'StrictHostKeyChecking={_hkc}',
             '-o', f'UserKnownHostsFile={_known_hosts}',
             '-o', 'LogLevel=ERROR',
             '-o', 'PreferredAuthentications=keyboard-interactive,password',
             '-o', 'HostKeyAlgorithms=+ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256',
             '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519',
             '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256']
        # NS Apr 2026 — ControlMaster opt-in. Adds connection-sharing args.
        # If the helper can't create the socket dir, returns []  → no-op.
        if use_controlmaster:
            try:
                from pegaprox.utils.ssh_pool import controlmaster_args
                ssh_args.extend(controlmaster_args(host, user))
            except Exception as _cm_err:
                # any import / setup error → fall through, ssh just runs without sharing
                pass
        ssh_args.extend([f'{user}@{host}', cmd])
        result = subprocess.run(
            ssh_args,
            capture_output=True, text=True, timeout=timeout, env=env
        )
        if result.returncode == 0:
            return result.returncode, result.stdout, result.stderr
        # sshpass also failed
        return result.returncode, result.stdout, result.stderr or last_err
    except Exception as sub_err:
        return 1, '', f'All SSH methods failed: {last_err}; subprocess: {sub_err}'


_node_ip_cache = {}  # (cluster_id, node) -> (ip, timestamp)

def _pve_node_exec(pve_mgr, node, cmd, timeout=600, use_controlmaster=True,
                   ignore_node_backoff=False):
    """Execute a command on a Proxmox node via the Proxmox API.
    Uses POST /nodes/{node}/execute or falls back to SSH.

    NS Apr 2026 — Phase 2: use_controlmaster=True enables OpenSSH connection
    sharing on the SSH fallback path. Multiple calls to the same node within
    300s reuse the master connection (skips TCP+crypto+auth handshake).
    Pass use_controlmaster=False for one-shot calls where you don't want a
    persistent socket (rare). HA-critical SSH in core/manager.py does NOT
    go through this function.

    MK May 2026 (dead-node UI hang) — short-circuit if the per-node circuit
    breaker says this node is unreachable; register failure on SSH errors so
    repeated calls don't burn a full timeout every time."""
    # MK — fail-fast if the breaker is open, unless the caller is already in a
    # controlled workflow that needs to probe the node to recover from a stale
    # breaker. V2P migration uses this for short local checks on the target node:
    # a failed remote ESXi backend probe must not block SSHFS/NBD fallbacks.
    if not ignore_node_backoff:
        try:
            blocked, remaining = pve_mgr._is_node_blocked(node)
            if blocked:
                return 1, '', f"node '{node}' in circuit-breaker backoff ({remaining}s remaining)"
        except Exception:
            # Older managers without the breaker — proceed as before
            pass

    # Method 1: Try Proxmox API exec (PVE 7.4+)
    try:
        resp = pve_mgr._api_post(
            f"https://{pve_mgr.host}:{pve_mgr.api_port}/api2/json/nodes/{node}/execute",
            data={'commands': cmd}
        )
        if resp.status_code == 200:
            try:
                pve_mgr._reset_node_failures(node)
            except Exception:
                pass
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
        # NS: use manager's _get_node_ip which does proper interface scoring
        # (same mgmt interface, same VLAN, same subnet, reachability probe)
        # Old code just grabbed first active non-lo interface which broke
        # on multi-homed nodes with dedicated storage NICs (#132)
        try:
            node_host = pve_mgr._get_node_ip(node)
        except Exception:
            pass

    if not node_host:
        # MK May 2026 — DO NOT silently fall back to pve_mgr.host when the
        # target node is unreachable. Previously this routed node-targeted
        # commands to the cluster.host node, which is wrong for anything
        # node-specific (running ps, reading /etc/pve/local, etc.). If
        # _get_node_ip returns None, register the failure and bail.
        try:
            pve_mgr._register_node_failure(node)
        except Exception:
            pass
        return 1, '', f"cannot resolve reachable IP for node '{node}'"

    # Cache the resolved IP
    _node_ip_cache[cache_key] = (node_host, time.time())

    # MK Sep 2026 — two things were wrong with the identity used here, and both end the
    # same way: a failed root login on somebody's hypervisor, repeated on every call.
    #
    # 1. The user was hardcoded to 'root'. core/xhm.py has always done
    #    `getattr(config, 'ssh_user', '') or 'root'`; this path never got the memo, so a
    #    cluster registered as e.g. backupadmin@pam with a dedicated SSH user was still
    #    offered root + the WEB password, which cannot work.
    # 2. Nothing asked whether we hold an SSH credential at all. ssh_diagnose already
    #    knows — including that config.pass_ holds the TOKEN SECRET under API-token auth
    #    (#717) — but only the compliance routes consulted it.
    #
    # The screendump behind the console tiles runs through here on every poll, so on a
    # cluster whose port 22 is reachable this produced a steady trickle of failed root
    # auth attempts. Observed live: two per screenshot, against a node whose own SSH
    # banner says all activity is logged and unauthorised access will be prosecuted.
    # Anything watching auth.log reads that as an attack on its own infrastructure, and
    # a fail2ban ban is IP-wide — it takes :8006 with it, so the API, the console and the
    # SSE stream go down together for the duration.
    try:
        _diag = None
        try:
            _diag = pve_mgr.ssh_diagnose(node)
        except Exception:
            pass   # older managers without the classifier — behave as before
        if _diag and _diag[0] == 'SSH_NO_CREDENTIALS':
            return 1, '', _diag[1]

        _ssh_user = getattr(pve_mgr.config, 'ssh_user', '') or 'root'
        # The diagnosis above still lets the worst case through: it only says "no
        # credentials" when there is NEITHER a key NOR a usable password, so a cluster
        # with an SSH key stored that authenticates with an API token comes back clean.
        # _ssh_exec is password-only (M3 passes look_for_keys=False, the sshpass leg asks
        # for keyboard-interactive,password), so the key is never reached and config.pass_
        # goes to sshd in its place — on a token cluster that is the token secret, and
        # every method in _ssh_exec tries it in turn. Key + API token is the setup we
        # recommend, so that is the config generating the most failed root logins.
        # Same question as ssh_diagnose asks, and for the same reason: pass_ is the token
        # secret only when the operator typed a token id as the username. A cluster whose
        # token WE minted (#110) keeps its password, and blanking it here took node
        # commands away from the most common configuration we have.
        _token_auth = '!' in (getattr(pve_mgr.config, 'user', '') or '')
        _ssh_pass = '' if _token_auth else (getattr(pve_mgr.config, 'pass_', '') or '')
        if not _ssh_pass:
            # Say which of the three it actually is. The first version of this asserted a
            # stored key in every case, but the branch is also reached on a cluster with no
            # credential at all — whenever ssh_diagnose raised and its own message never
            # got the chance to say so.
            _why = ("this cluster authenticates with an API token, and the stored secret is "
                    "that token, not an SSH password") if _token_auth else \
                   "no SSH password is stored for this cluster"
            if getattr(pve_mgr.config, 'ssh_key', ''):
                _why += (" — the stored SSH key cannot help here, this path authenticates "
                         "by password only")
            return 1, '', f"cannot run node commands on '{node}': {_why}"
        rc, out, err = _ssh_exec(node_host, _ssh_user, _ssh_pass, cmd,
                                  timeout=timeout, use_controlmaster=use_controlmaster)
        # SSH error patterns that indicate the node itself is dead, not the cmd
        looks_like_node_down = (
            rc != 0 and any(s in str(err).lower() for s in (
                'tcp connect', 'connection refused', 'connection timed out',
                'no route to host', 'host is down', 'auth failed',
                # MK Sep 2026 — 'auth failed' never matched anything paramiko says. Its
                # message is "Authentication (keyboard-interactive) failed." and the
                # substring 'auth failed' does not occur in it, so the breaker sat idle
                # through exactly the failures it was added to throttle and we kept
                # re-offering credentials to sshd on every poll.
                'authentication failed', 'authentication (',
                # OpenSSH's own rejection from the subprocess leg. Deliberately the
                # long form: a bare 'permission denied' is also what a COMMAND says
                # when it fails on the node, and that must not mark the node dead.
                'permission denied (publickey',
                'paramiko exec failed', 'all ssh methods failed',
            ))
        )
        try:
            if looks_like_node_down:
                pve_mgr._register_node_failure(node)
            elif rc == 0:
                pve_mgr._reset_node_failures(node)
        except Exception:
            pass
        return rc, out, err
    except Exception as e:
        try:
            pve_mgr._register_node_failure(node)
        except Exception:
            pass
        return 1, '', str(e)


