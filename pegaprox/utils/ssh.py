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
import ipaddress
import re
import hashlib

from pegaprox.constants import SSH_MAX_CONCURRENT
from pegaprox.utils.ssh_security import apply_host_key_policy, persist_host_keys, verify_transport_host_key
from pegaprox.models.tasks import ssh_port_of
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
                # passing them in from a request.
                #
                # MK Sep 2026 (follow-up) - this used to evict `next(iter(...))`, which on
                # an insertion-ordered dict is the FIRST bucket ever created, i.e. one of
                # the literal ones the real login paths have been counting in since boot.
                # Evicting a window resets it, so the defence against a caller-chosen
                # budget would have cleared the rate limit protecting password change or
                # TOTP verification - it fed the attack it was meant to stop. Refuse the
                # unknown budget instead: nothing is evicted, the map cannot grow, and a
                # caller doing this gets a 429 rather than a reset. Unreachable today (four
                # call sites, three distinct literal pairs) and it should stay that way.
                logging.warning(
                    '[RATELIMIT] auth-action budgets exceeded %d distinct pairs - refusing '
                    '%s rather than evicting an established window. A caller is choosing '
                    'the budget; it should be a literal.',
                    _AUTH_ACTION_MAX_BUCKETS, bucket)
                return False
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


def is_ipv6_literal(h):
    """A plain IPv6 address. A zone is allowed only as an interface name
    (fe80::1%eth0): ipaddress takes any text after the '%', '$(id)' too."""
    h = str(h or '')
    try:
        ipaddress.IPv6Address(h)
    except ValueError:
        return False
    zone = h.partition('%')[2]
    return not zone or re.fullmatch(r'[A-Za-z0-9_.@-]{1,15}', zone) is not None


def bare_host(host):
    """'[2001:db8::1]' -> '2001:db8::1', anything else unchanged.
    sockets, paramiko and ssh want the plain address, only URLs and scp/rsync
    'user@[addr]:path' targets take the brackets (#1158).
    Only a real IPv6 literal loses its brackets - '[-oProxyCommand=x]' stays as it
    is and simply does not resolve."""
    h = str(host or '').strip()
    if h.startswith('[') and h.endswith(']') and is_ipv6_literal(h[1:-1]):
        return h[1:-1]
    return h


def ssh_login_args(user, host):
    """The end of an OpenSSH argv: ['-l', user, '--', host]. The login name is checked
    and travels as the value of -l, and '--' ends option parsing before the host, so
    neither can be read as an option (the command after it neither). Raises ValueError
    for a user that is not a login name."""
    from pegaprox.utils.sanitization import validate_ssh_user
    if not validate_ssh_user(user):
        raise ValueError(f'refusing SSH login name {str(user)[:40]!r}: not a valid user name')
    return ['-l', user, '--', str(host)]


def _feed_stdin(stdin, data):
    """Hand `data` to a remote command's stdin and close it, so a read there sees the end.
    A channel that went away is the command's problem: it reads nothing and says so."""
    try:
        stdin.write(data)
        stdin.flush()
    except Exception:
        pass
    try:
        stdin.channel.shutdown_write()
    except Exception:
        pass


def _ssh_exec(host, user, password, cmd, timeout=30, use_controlmaster=False,
              connect_timeout=8, stdin_data=None, port=22):
    """Execute command on remote host via SSH.
    Handles ESXi which only allows 'keyboard-interactive' and 'publickey'.

    stdin_data: text for the command's stdin, for a secret that must not be part of
    `cmd` (a command line is readable by every local account while it runs).

    port: the SSH port. A node behind a per-node forward (node_endpoints) answers on its
    own, and its address then belongs to the forward, whose port 22 is not the node.

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
    # one spelling from here on: the guard, the host-key pin, the TCP connect and the ssh
    # argv all see the address that is dialled, never '[addr]' (#1158)
    host = bare_host(host)
    last_err = ''
    errors = []
    try:
        login_args = ssh_login_args(user, host)
    except ValueError as e:
        return 1, '', str(e)
    # one exit, both ways out below (#625): asked before anything connects, and again
    # right before the command goes out either way
    from pegaprox.core import ha_transport
    from pegaprox.core.ha import GuardRefused
    ha_transport.guard_ssh(host, cmd)

    def _make_sock():
        """Pre-create socket with explicit connect_timeout — paramiko.Transport
        won't fail-fast on dead hosts otherwise.  IPv4 + IPv6 aware."""
        try:
            return _socket.create_connection((host, port), timeout=connect_timeout)
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
                raise Exception(f'TCP connect to {host}:{port} timed out after {connect_timeout}s')
            transport = paramiko.Transport(_sock)
            _configure_transport_algorithms(transport)
            transport.connect()
            # verify the server key BEFORE sending credentials (a manual Transport
            # bypasses the SSHClient host-key policy). Raises on changed/unknown key.
            verify_transport_host_key(transport, host, paramiko, port=port)

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
                    raise Exception(f'TCP connect to {host}:{port} timed out after {connect_timeout}s')
                transport2 = paramiko.Transport(_sock2)
                _configure_transport_algorithms(transport2)
                transport2.connect()
                verify_transport_host_key(transport2, host, paramiko, port=port)

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
                client3.connect(host, port=port, username=user, password=password,
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

        # Execute command (the connects above may have taken a while: checked again, #625)
        try:
            ha_transport.guard_ssh(host, cmd, again=True)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            if stdin_data is not None:
                _feed_stdin(stdin, stdin_data)
            out = read_capped(stdout)
            err = read_capped(stderr)
            rc = stdout.channel.recv_exit_status()
            client.close()
            return rc, out, err
        except Exception as e:
            try: client.close()
            except: pass
            if isinstance(e, GuardRefused):
                raise
            raise Exception(f'Paramiko exec failed: {e}')

    except GuardRefused:
        raise
    except Exception as paramiko_err:
        last_err = str(paramiko_err)
    
    # Fallback: sshpass + ssh subprocess (handles keyboard-interactive via PreferredAuthentications)
    try:
        from pegaprox.utils.ssh_security import cli_hostkey_opts
        env = os.environ.copy()
        env['SSHPASS'] = password
        # accept-new = TOFU (accept unknown, REJECT a changed key). strict mode and a
        # standby upgrade to `yes` (reject unknown too). Keeps the system-ssh fallback's
        # host-key behaviour in lock-step with the paramiko paths.
        _hkc = cli_hostkey_opts()[0]
        ssh_args = ['sshpass', '-e', 'ssh', '-p', str(int(port or 22)),
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
        ssh_args.extend(login_args + [cmd])
        # ssh hands its stdin on to the remote command
        extra = {} if stdin_data is None else {'input': stdin_data}
        # long after the guard was asked at the top: checked again, bounded and in a
        # process group of its own in an automatic group (#625)
        result = ha_transport.node_cmd(
            ssh_args, capture_output=True, text=True, timeout=timeout, env=env,
            host=host, again=True, **extra
        )
        if result.returncode == 0:
            return result.returncode, result.stdout, result.stderr
        # sshpass also failed
        return result.returncode, result.stdout, result.stderr or last_err
    except GuardRefused:
        raise
    except Exception as sub_err:
        return 1, '', f'All SSH methods failed: {last_err}; subprocess: {sub_err}'


def node_login(config):
    """The user every SSH path logs in to this cluster's nodes as: the cluster's SSH user,
    root when none is set.

    MK Nov 2026 (#1322) - there were two rules. About half the paths took the name of
    the API user ('pegaprox@pve' -> 'pegaprox') and the other half root, so a cluster
    with a key for root got failed logins as an account that is not on the node, and one
    with a sudo account got failed root logins from the sensor and BMC reads every hour.
    The dialog and the docs always said root unless an SSH user is set.
    """
    user = getattr(config, 'ssh_user', '') or ''
    return (user.strip() if isinstance(user, str) else '') or 'root'


def ssh_password_for(config):
    """The password an SSH login to this PVE cluster's nodes may offer - '' for none.

    MK Oct 2026 - pass_ is only an SSH password when config.user is an account. With a
    token id typed as the username ('user@realm!tokenid') it is the token SECRET, and
    every ladder that went key -> BatchMode -> sshpass handed it to sshd whenever the
    key was refused (#717 class). ssh_blocked_reason did not catch that: a stored key
    is enough for it to say go. The marker is '!' in user, not _using_api_token - a
    token we minted ourselves (#110) leaves pass_ the account password. The marker holds
    only while user and pass_ change together, which is why the cluster edit routes do
    not take 'user' on its own.
    Use this (or PegaProxManager.ssh_password_to_offer) for every password step,
    never config.pass_ directly.

    MK Nov 2026 (#1322) - and only for the login it belongs to. An @pam account's
    password is that Linux user's on the node; any other realm's password is no password
    on the node at all. Offered to a different login it was one more failed login there.
    """
    if bool(getattr(config, 'ssh_disabled', False)):
        return ''
    user = getattr(config, 'user', '') or ''
    user = user if isinstance(user, str) else ''
    if '!' in user:
        return ''
    name, _, realm = user.partition('@')
    if realm not in ('', 'pam') or (name or 'root') != node_login(config):
        return ''
    return getattr(config, 'pass_', '') or ''


def ssh_password_to(mgr, host):
    """The password an SSH login to `host` of this manager's cluster may offer, '' for none.

    MK Oct 2026 (#1136) - the node at `host` gets its own root password where it has one,
    the cluster's otherwise (PegaProxManager.ssh_password_to_offer). For the paths outside
    the manager that build their own login; config.pass_ directly stays wrong there too.
    """
    offer = getattr(mgr, 'ssh_password_to_offer', None)
    if callable(offer):
        found = offer(host)
        if isinstance(found, str):
            return found
    return ssh_password_for(getattr(mgr, 'config', None))


def ssh_blocked_for(mgr, host=None):
    """Why SSH to this manager's nodes must not happen - a code, or None.

    For the routes that build their own paramiko client from config.ssh_key: blanking the
    password was not enough there, the key still logged in with SSH switched off (#941).
    Managers without ssh_blocked_reason (XCP-ng) answer by the switch alone. `host`: the
    address about to be dialled, which may hold a credential of its own (#1136).
    """
    probe = getattr(mgr, 'ssh_blocked_reason', None)
    if callable(probe):
        reason = probe(host) if host is not None else probe()
        return reason if isinstance(reason, str) else None
    if bool(getattr(getattr(mgr, 'config', None), 'ssh_disabled', False)):
        return 'SSH_DISABLED'
    return None


_node_ip_cache = {}  # (cluster_id, node) -> (ip, timestamp)

# MK Nov 2026 (#1224) - nodes whose sshd refused the stored key. The console tiles run
# node commands on every poll, and a key offered each time to a node that never takes
# it is a failed login per tile (OpenSSH's PerSourcePenalties then shuts PegaProx out).
# Only the server's own no counts. Offered again once this runs out, at once for another
# key or login name, after a login with the key went through there, and when an ESXi
# import starts.
_KEY_REFUSED_TTL = 300
_node_key_refused = {}  # (cluster_id, node) -> (monotonic, digest of login + key, why, host)


def _key_digest(login, key):
    return hashlib.sha256(f'{login}\0{key}'.encode('utf-8', 'replace')).hexdigest()


def key_accepted(cluster_id, host, login, key):
    """A login with `key` as `login` went through at `host` (the connection check, say):
    a refusal of it remembered for that address is out of date."""
    if not key or not _node_key_refused:
        return
    digest, addr = _key_digest(login, key), bare_host(host)
    for slot, seen in list(_node_key_refused.items()):
        if slot[0] == cluster_id and seen[1] == digest and seen[3] == addr:
            _node_key_refused.pop(slot, None)


def forget_key_refusal(pve_mgr, node):
    """The next command on `node` offers the stored key again: for a run an operator just
    started, after fixing what refused it perhaps."""
    _node_key_refused.pop((getattr(pve_mgr, 'id', None), node), None)


def _is_cluster_member(pve_mgr, node):
    """Whether `node` is in the manager's own node list. An empty or unreadable list is no."""
    if not isinstance(node, str) or not node:
        return False
    try:
        return node in (pve_mgr.nodes or {})
    except Exception:
        return False


def _run_on_client(client, cmd, timeout, stdin_data=None):
    """(rc, out, err) of one command on a connected paramiko client, which is closed after.

    One deadline of `timeout` for the call: stdout is read to EOF or until `timeout` passes
    without a byte, stderr and the exit status get what is left. recv_exit_status alone
    waits for ever; past the deadline the call answers 124 (what coreutils' timeout says)
    while the command may still be running. stdin_data goes to the command's stdin."""
    deadline = time.monotonic() + max(1, timeout)
    try:
        _in, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        if stdin_data is not None:
            _feed_stdin(_in, stdin_data)
        ch = stdout.channel
        out = read_capped(stdout)
        try:
            ch.settimeout(max(0.0, deadline - time.monotonic()))
        except Exception:
            pass
        err = read_capped(stderr)
        # counted, so a clock that stands still cannot keep it going
        for _ in range(int(max(0.0, deadline - time.monotonic()) / 0.2) + 1):
            if ch.exit_status_ready():
                break
            time.sleep(0.2)
        if ch.exit_status_ready():
            return ch.recv_exit_status(), out, err
        note = f"no exit status from the node within {timeout}s"
        return 124, out, f"{err.rstrip()}\n{note}" if err.strip() else note
    finally:
        try:
            client.close()
        except Exception:
            pass


def _stored_key_exec(pve_mgr, node, host, user, cmd, timeout, fallback, stdin_data=None):
    """The stored key's go at a node command, before any password (#1224).

    Through pve_mgr._ssh_connect: it asks ssh_blocked_reason, checks the host key the
    TOFU way and waits for the connection semaphore (no longer than the call's own
    timeout here). Returns (result, note): result is (rc, out, err) when this settles the
    call, None when the password step goes next; note says what became of the key.
    `fallback`: a password step follows. Without one a failed key login is the last one
    of this call and counts against the node; nothing counts that never reached it.
    `host` comes resolved: _pve_node_exec has it from _get_node_ip for a member only."""
    key = getattr(pve_mgr.config, 'ssh_key', '') or ''
    if not key or not hasattr(pve_mgr, '_ssh_connect'):
        return None, ''
    slot = (getattr(pve_mgr, 'id', None), node)
    digest = _key_digest(user, key)
    seen = _node_key_refused.get(slot)
    if seen and seen[1] == digest:
        left = int(_KEY_REFUSED_TTL - (time.monotonic() - seen[0]))
        if left > 0:
            return None, (f"the stored SSH key was refused for '{user}' ({seen[2]}), "
                          f"it is offered again in {left}s")
    _node_key_refused.pop(slot, None)

    # asked before anything connects, as _ssh_exec does (#625); the client's own ask at
    # the exec is then this same call once more
    from pegaprox.core import ha_transport
    ha_transport.guard_ssh(host, cmd)

    failure = {}
    try:
        client = pve_mgr._ssh_connect(host, retries=1, connect_timeout=8, failure=failure,
                                      login=user, quiet=True, guard_asked=True,
                                      queue_wait=min(120, max(10, int(timeout))), node=node)
    except Exception as e:
        client, failure = None, {'kind': 'error', 'detail': str(e)}
    if client is not None:
        result = _run_on_client(client, cmd, timeout, stdin_data=stdin_data)
        # logged in: whatever the command said, the node answers
        try:
            pve_mgr._reset_node_failures(node)
        except Exception:
            pass
        return result, ''

    kind = failure.get('kind') or 'local'
    detail = ' '.join(str(failure.get('detail') or 'no connection was opened').split())[:300]
    if kind == 'auth' and failure.get('refused') is False:
        # the connection ended or stalled during the login: no answer about the key
        kind = 'error'
    if kind == 'blocked':
        return (1, '', f"cannot run node commands on '{node}': {detail}"), ''
    if kind in ('busy', 'local'):
        # nothing went to the node: no count against it, nothing to remember
        return None, f"the stored SSH key was not tried ({detail})"
    if kind in ('unreachable', 'host_key') or (kind in ('auth', 'error') and not fallback):
        try:
            pve_mgr._register_node_failure(node)
        except Exception:
            pass
    if kind in ('unreachable', 'host_key'):
        # nothing a password could change: the node is not there, or not the one pinned
        what = 'host key check failed' if kind == 'host_key' else 'connection failed'
        return (1, '', f"SSH to node '{node}' at {host}: {what}: {detail}"), ''
    if kind in ('auth', 'key'):
        _node_key_refused[slot] = (time.monotonic(), digest, detail, bare_host(host))
        if kind == 'key':
            return None, f"the stored SSH key could not be loaded ({detail})"
        return None, f"the stored SSH key was refused for '{user}' ({detail})"
    return None, f"SSH with the stored key failed ({detail})"


def _pve_node_exec(pve_mgr, node, cmd, timeout=600, use_controlmaster=True,
                   ignore_node_backoff=False, stdin_data=None):
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
    repeated calls don't burn a full timeout every time.

    MK Nov 2026 (#1224) - SSH offers the stored key first (_stored_key_exec), the
    password after it. use_controlmaster only concerns the password leg's ssh. Only a
    node of the manager's own node list gets a command at all.

    stdin_data: text the command reads on stdin, for a secret that must stay off its
    command line. Such a call goes over SSH only, the API call has no stdin."""
    # MK Nov 2026 (#1224) - routes hand node names on from the URL, and _get_node_ip's DNS
    # step resolves any name: the stored key, or the password, went to whatever address
    # that gave. A name the cluster does not list gets nothing, an unknown list neither.
    if not _is_cluster_member(pve_mgr, node):
        return 1, '', f"cannot run node commands on '{str(node)[:64]}': not a node of this cluster"
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

    # Method 1: Try Proxmox API exec (PVE 7.4+). It has no stdin to hand on.
    if stdin_data is None:
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
        # MK Sep 2026 (#941) — SSH_DISABLED belongs here too. There are two ways out of
        # this process to a node: paramiko via manager._ssh_connect, and this shell-out.
        # An off switch that only closed one of them would be worth nothing.
        if _diag and _diag[0] in ('SSH_NO_CREDENTIALS', 'SSH_DISABLED'):
            return 1, '', _diag[1]

        _ssh_user = node_login(pve_mgr.config)
        # The diagnosis above lets a cluster with a key through, token or not. _ssh_exec
        # is password-only (M3 passes look_for_keys=False, the sshpass leg asks for
        # keyboard-interactive,password), so the key goes first, on its own client: key +
        # API token is the setup we recommend, and on key-only nodes it was the setup
        # that could not run a single node command (#1224).
        # Same question as ssh_diagnose asks, and for the same reason: pass_ is the token
        # secret only when the operator typed a token id as the username. A cluster whose
        # token WE minted (#110) keeps its password, and blanking it here took node
        # commands away from the most common configuration we have.
        _token_auth = '!' in (getattr(pve_mgr.config, 'user', '') or '')
        # the node's own password where it has one (#1136)
        _ssh_pass = ssh_password_to(pve_mgr, node_host)
        settled, _key_note = _stored_key_exec(pve_mgr, node, node_host, _ssh_user, cmd,
                                              timeout, fallback=bool(_ssh_pass),
                                              stdin_data=stdin_data)
        if settled is not None:
            return settled
        if not _ssh_pass:
            # Say which of the three it actually is. The first version of this asserted a
            # stored key in every case, but the branch is also reached on a cluster with no
            # credential at all — whenever ssh_diagnose raised and its own message never
            # got the chance to say so.
            _why = ("this cluster authenticates with an API token, and the stored secret is "
                    "that token, not an SSH password, and this node has no password of its "
                    "own") if _token_auth else \
                   "no SSH password is stored for this cluster"
            if _key_note:
                _why = f"{_key_note}, and {_why}"
            elif getattr(pve_mgr.config, 'ssh_key', ''):
                # a manager without _ssh_connect has no way to the key
                _why += (" - the stored SSH key cannot be used with this manager, and this "
                         "path then authenticates by password only")
            return 1, '', f"cannot run node commands on '{node}': {_why}"
        rc, out, err = _ssh_exec(node_host, _ssh_user, _ssh_pass, cmd,
                                  timeout=timeout, use_controlmaster=use_controlmaster,
                                  stdin_data=stdin_data, port=ssh_port_of(pve_mgr.config, node))
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
        if looks_like_node_down and _key_note:
            err = f"{err} (before that, {_key_note})"
        return rc, out, err
    except Exception as e:
        from pegaprox.core.ha import GuardRefused
        if isinstance(e, GuardRefused):
            # this instance may not send it (#625): that says nothing about the node
            return 1, '', str(e)
        try:
            pve_mgr._register_node_failure(node)
        except Exception:
            pass
        return 1, '', str(e)


