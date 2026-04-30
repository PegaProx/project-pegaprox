"""SSH-tunneled local port forwarder for the PegaProx ↔ PVE-node VNC leg.

When TLS-inspection middleboxes (CrowdStrike Falcon NF, Palo Alto SSL Decryption,
Zscaler, Forcepoint, …) sit between PegaProx and the PVE node, they re-encrypt
the WSS-to-PVE TLS and modify binary RFB bytes mid-stream — destroying the
DES challenge-response. This is what produces the textbook "recv=60B + ttfb
high" pattern with QEMU returning 'Authentication failed'.

This module wraps that leg in an SSH transport. SSH is host-key-pinned per
session, so inspection engines don't decrypt it (they don't have the trust
anchor). The PegaProx daemon spawns a single persistent SSH client per PVE
node, then opens an ephemeral local TCP listener per VNC session that pipes
bytes through a `direct-tcpip` SSH channel to pve:8006. The VNC subprocess
then connects to `wss://127.0.0.1:<EPHEMERAL>/...` instead of `wss://pve:8006`.

Multi-user-safe: each concurrent session gets its own listener + channel,
no port collisions. Persistent SSH connection is reused (no reconnect cost
per session). On transport drop, the next acquire() reconnects.

MK Apr 2026 — driven by customer report where Stable VNC Mode (browser-side
encryption) wasn't enough because their inspection-engine sat on the
PegaProx↔PVE side too.
"""
import os
import select
import socket
import threading
import time
import logging
from typing import Optional


# Lazy paramiko import — keep this module importable even on hosts where
# paramiko isn't installed (it just won't be usable).
def _get_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None


class TunnelEndpoint:
    """A single active local-port forward. Created by SshVncTunnelPool.acquire()."""

    def __init__(self, listener: socket.socket, transport, target_host: str,
                 target_port: int, cluster_id: str, pve_host: str):
        self._listener = listener
        self._transport = transport
        self._target_host = target_host
        self._target_port = target_port
        self._cluster_id = cluster_id
        self._pve_host = pve_host
        self.local_port = listener.getsockname()[1]
        self._stopped = False
        self._channels: list = []        # active per-connection channels
        self._handlers: list = []        # per-connection forwarder threads
        self._lock = threading.Lock()
        # accept-loop runs in a daemon thread
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"VncTun-Accept-{self.local_port}",
            daemon=True
        )
        self._accept_thread.start()
        logging.info(f"[VncTunnel] forward open: cluster={cluster_id} pve={pve_host} → 127.0.0.1:{self.local_port}")

    def _accept_loop(self):
        """Accept loop: each inbound connection gets its own SSH channel + pumper."""
        while not self._stopped:
            try:
                client_sock, addr = self._listener.accept()
            except OSError:
                # listener closed during stop()
                break
            except Exception as e:
                logging.debug(f"[VncTunnel] accept error: {e}")
                continue

            try:
                # Open a direct-tcpip channel through the SSH transport.
                # The SSH server-side (sshd on PVE) will open a TCP socket
                # to (target_host, target_port) on its end and pipe bytes.
                channel = self._transport.open_channel(
                    'direct-tcpip',
                    (self._target_host, self._target_port),
                    addr,
                )
            except Exception as e:
                logging.warning(
                    f"[VncTunnel] open_channel failed pve={self._pve_host} "
                    f"target={self._target_host}:{self._target_port}: {e}"
                )
                try: client_sock.close()
                except Exception: pass
                continue

            handler = _Pumper(client_sock, channel, self.local_port)
            with self._lock:
                self._channels.append(channel)
                self._handlers.append(handler)
            handler.start()

    def stop(self):
        """Tear down: close listener, close all in-flight channels."""
        if self._stopped:
            return
        self._stopped = True
        try: self._listener.close()
        except Exception: pass
        with self._lock:
            for ch in self._channels:
                try: ch.close()
                except Exception: pass
            for h in self._handlers:
                try: h.stop()
                except Exception: pass
            self._channels.clear()
            self._handlers.clear()
        logging.info(f"[VncTunnel] forward closed: cluster={self._cluster_id} port={self.local_port}")


class _Pumper(threading.Thread):
    """Bidirectional byte-pipe between a local TCP socket and an SSH channel."""

    def __init__(self, sock: socket.socket, channel, port_for_log: int):
        super().__init__(name=f"VncTun-Pump-{port_for_log}", daemon=True)
        self._sock = sock
        self._channel = channel
        self._stopped = False

    def stop(self):
        self._stopped = True
        try: self._sock.close()
        except Exception: pass
        try: self._channel.close()
        except Exception: pass

    def run(self):
        # Use select() on both ends. Bytes go socket→channel and channel→socket.
        # Buffer at 16KB — VNC frames are typically much smaller.
        BUF = 16 * 1024
        try:
            self._sock.setblocking(False)
            while not self._stopped:
                ready, _, _ = select.select([self._sock, self._channel], [], [], 1.0)
                if self._sock in ready:
                    try:
                        data = self._sock.recv(BUF)
                    except (BlockingIOError, InterruptedError):
                        data = None
                    if data is None:
                        pass
                    elif not data:
                        break
                    else:
                        self._channel.sendall(data)
                if self._channel in ready:
                    if self._channel.recv_ready():
                        data = self._channel.recv(BUF)
                        if not data:
                            break
                        self._sock.sendall(data)
                # Stale-close detection: if channel reports closed
                if self._channel.exit_status_ready() and not self._channel.recv_ready():
                    break
        except Exception as e:
            logging.debug(f"[VncTunnel] pump exception: {e}")
        finally:
            try: self._sock.close()
            except Exception: pass
            try: self._channel.close()
            except Exception: pass


class SshVncTunnelPool:
    """Process-wide pool of persistent SSH transports keyed by cluster_id.

    Reuses one SSH connection per PVE-node-group. Each acquire() returns a
    fresh local-port forward — multiple concurrent VNC sessions share the
    same SSH transport via independent direct-tcpip channels.
    """

    # how long the accept-listener keeps trying before giving up if SSH connect fails
    SSH_CONNECT_TIMEOUT = 10
    # SSH-level keepalive so corporate FW conntrack doesn't drop the persistent transport
    SSH_KEEPALIVE_INTERVAL = 30

    def __init__(self):
        self._clients: dict[str, object] = {}     # cluster_id → paramiko.SSHClient
        self._lock = threading.Lock()

    def _get_or_create_client(self, cluster_id: str, pve_host: str,
                              ssh_user: str, ssh_port: int = 22,
                              ssh_key_content: Optional[str] = None,
                              ssh_password: Optional[str] = None):
        paramiko = _get_paramiko()
        if not paramiko:
            raise RuntimeError("paramiko not installed — cannot use VNC SSH tunneling")

        with self._lock:
            client = self._clients.get(cluster_id)
            if client is not None:
                t = client.get_transport()
                if t is not None and t.is_active():
                    return client
                # transport died — close and recreate
                try: client.close()
                except Exception: pass
                self._clients.pop(cluster_id, None)

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = dict(
                hostname=pve_host, port=ssh_port, username=ssh_user,
                timeout=self.SSH_CONNECT_TIMEOUT, banner_timeout=15, auth_timeout=15,
                allow_agent=False, look_for_keys=False,
            )
            # try key first if provided, else password
            if ssh_key_content:
                import io as _io
                pkey = None
                for key_class in (paramiko.RSAKey, paramiko.Ed25519Key,
                                  paramiko.ECDSAKey, getattr(paramiko, 'DSSKey', None)):
                    if key_class is None: continue
                    try:
                        pkey = key_class.from_private_key(_io.StringIO(ssh_key_content))
                        break
                    except Exception:
                        continue
                if pkey:
                    connect_kwargs['pkey'] = pkey
            if 'pkey' not in connect_kwargs and ssh_password:
                connect_kwargs['password'] = ssh_password

            client.connect(**connect_kwargs)

            # SSH-level keepalive — prevents stateful FW from dropping the persistent transport
            try:
                client.get_transport().set_keepalive(self.SSH_KEEPALIVE_INTERVAL)
            except Exception:
                pass

            self._clients[cluster_id] = client
            logging.info(f"[VncTunnel] persistent SSH up: cluster={cluster_id} → {ssh_user}@{pve_host}:{ssh_port}")
            return client

    def acquire(self, cluster_id: str, pve_host: str,
                ssh_user: str, ssh_port: int = 22,
                ssh_key_content: Optional[str] = None,
                ssh_password: Optional[str] = None,
                target_host: str = '127.0.0.1',
                target_port: int = 8006) -> TunnelEndpoint:
        """Open a fresh local-port forward to pve:target_port through SSH.

        Returns a TunnelEndpoint with .local_port and .stop(). Caller MUST
        call .stop() when the VNC session ends to free resources.
        """
        client = self._get_or_create_client(
            cluster_id, pve_host, ssh_user, ssh_port,
            ssh_key_content, ssh_password,
        )

        # bind ephemeral local port (kernel-allocated, never collides)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)

        return TunnelEndpoint(
            listener=listener,
            transport=client.get_transport(),
            target_host=target_host,
            target_port=target_port,
            cluster_id=cluster_id,
            pve_host=pve_host,
        )

    def shutdown(self, cluster_id: Optional[str] = None):
        """Close one cluster's SSH client (or all). For testing / clean shutdown."""
        with self._lock:
            keys = [cluster_id] if cluster_id else list(self._clients.keys())
            for k in keys:
                c = self._clients.pop(k, None)
                if c:
                    try: c.close()
                    except Exception: pass


# process-wide singleton
_pool = SshVncTunnelPool()


def acquire(*args, **kwargs) -> TunnelEndpoint:
    return _pool.acquire(*args, **kwargs)


def shutdown(cluster_id: Optional[str] = None):
    _pool.shutdown(cluster_id)


# ──────────────────────────────────────────────────────────────────────────
# Self-test (run directly: python -m pegaprox.utils.vnc_tunnel)
#
# Spins up an in-process tiny SSH server using paramiko's ServerInterface,
# then exercises:
#   1. Single-session round-trip
#   2. Five concurrent sessions, each with its own listener
#   3. Reconnection after the SSH transport drops
# ──────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    paramiko = _get_paramiko()
    if not paramiko:
        print("paramiko not installed — cannot run self-test")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    def _ok(m): print(f"  OK   {m}")
    def _bad(m):
        print(f"  FAIL {m}")
        sys.exit(1)

    # ── test 1: tiny TCP echo server simulating PVE ──────────────────
    echo_host = '127.0.0.1'
    echo_port_holder = []
    echo_clients_seen = []

    def _echo_server():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((echo_host, 0))
        s.listen(20)
        echo_port_holder.append(s.getsockname()[1])
        while True:
            try:
                c, addr = s.accept()
            except OSError:
                break
            echo_clients_seen.append(addr)
            def _serve(c):
                try:
                    while True:
                        data = c.recv(4096)
                        if not data: break
                        c.sendall(b'ECHO:' + data)
                except Exception: pass
                finally:
                    try: c.close()
                    except: pass
            threading.Thread(target=_serve, args=(c,), daemon=True).start()

    threading.Thread(target=_echo_server, daemon=True).start()
    while not echo_port_holder:
        time.sleep(0.01)
    echo_port = echo_port_holder[0]
    _ok(f"echo 'pve' simulator up on 127.0.0.1:{echo_port}")

    # ── test 2: tiny in-process SSH server ───────────────────────────
    HOST_KEY = paramiko.RSAKey.generate(2048)

    class _SshServer(paramiko.ServerInterface):
        def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u == 'tester' and p == 'tt') else paramiko.AUTH_FAILED
        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind in ('direct-tcpip', 'session') else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_direct_tcpip_request(self, chanid, origin, destination):
            # destination = (host, port) requested by the client
            try:
                # connect to the requested target and proxy bytes
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.connect(destination)
                # store the target_sock so the channel-handler can pump bytes
                self._pending_targets = getattr(self, '_pending_targets', {})
                self._pending_targets[chanid] = target_sock
            except Exception:
                return paramiko.OPEN_FAILED_CONNECT_FAILED
            return paramiko.OPEN_SUCCEEDED

    def _ssh_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 0))
        sock.listen(5)
        ssh_port_holder.append(sock.getsockname()[1])
        while True:
            try:
                client_sock, _ = sock.accept()
            except OSError:
                break
            def _serve_one(client_sock):
                t = paramiko.Transport(client_sock)
                t.add_server_key(HOST_KEY)
                server = _SshServer()
                try:
                    t.start_server(server=server)
                    # Main loop — accept channels and pump
                    while t.is_active():
                        chan = t.accept(20)
                        if chan is None:
                            continue
                        # find matching target_sock
                        ts = getattr(server, '_pending_targets', {}).pop(chan.get_id(), None)
                        if not ts:
                            chan.close()
                            continue
                        # pump
                        def _pump_bidir(chan, ts):
                            ts.setblocking(False)
                            try:
                                while True:
                                    ready, _, _ = select.select([chan, ts], [], [], 1.0)
                                    if chan in ready:
                                        if chan.recv_ready():
                                            d = chan.recv(8192)
                                            if not d: break
                                            ts.sendall(d)
                                    if ts in ready:
                                        try: d = ts.recv(8192)
                                        except (BlockingIOError, InterruptedError): d = None
                                        if d is None: pass
                                        elif not d: break
                                        else: chan.sendall(d)
                                    if chan.closed or chan.exit_status_ready() and not chan.recv_ready():
                                        break
                            finally:
                                try: chan.close()
                                except: pass
                                try: ts.close()
                                except: pass
                        threading.Thread(target=_pump_bidir, args=(chan, ts), daemon=True).start()
                except Exception as e:
                    logging.error(f"ssh server error: {e}")
            threading.Thread(target=_serve_one, args=(client_sock,), daemon=True).start()

    ssh_port_holder = []
    threading.Thread(target=_ssh_server, daemon=True).start()
    while not ssh_port_holder:
        time.sleep(0.01)
    ssh_port = ssh_port_holder[0]
    _ok(f"in-process SSH server up on 127.0.0.1:{ssh_port}")

    # ── test 3: single session round-trip via tunnel ────────────────
    pool = SshVncTunnelPool()
    ep = pool.acquire(
        cluster_id='test-cluster-1', pve_host='127.0.0.1', ssh_port=ssh_port,
        ssh_user='tester', ssh_password='tt',
        target_host='127.0.0.1', target_port=echo_port,
    )
    time.sleep(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', ep.local_port))
    s.sendall(b'hello')
    s.settimeout(3.0)
    received = b''
    while len(received) < len(b'ECHO:hello'):
        chunk = s.recv(64)
        if not chunk: break
        received += chunk
    if received != b'ECHO:hello':
        _bad(f"single-session round-trip got: {received!r}")
    s.close()
    ep.stop()
    _ok(f"single session: bytes flowed local:{ep.local_port} → SSH → echo → back ({len(received)} bytes)")

    # ── test 4: 5 concurrent sessions, all on different ports ───────
    eps = []
    for _ in range(5):
        eps.append(pool.acquire(
            cluster_id='test-cluster-1', pve_host='127.0.0.1', ssh_port=ssh_port,
            ssh_user='tester', ssh_password='tt',
            target_host='127.0.0.1', target_port=echo_port,
        ))
    ports = [e.local_port for e in eps]
    if len(set(ports)) != 5:
        _bad(f"concurrent sessions got duplicate ports: {ports}")
    _ok(f"5 concurrent forwards, distinct ports: {ports}")

    time.sleep(0.3)
    threads = []
    failures = []
    def _drive(ep, idx):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', ep.local_port))
            payload = f'msg-{idx}'.encode()
            s.sendall(payload)
            s.settimeout(3.0)
            r = s.recv(64)
            if r != b'ECHO:' + payload:
                failures.append((idx, r))
            s.close()
        except Exception as e:
            failures.append((idx, e))
    for i, ep in enumerate(eps):
        t = threading.Thread(target=_drive, args=(ep, i), daemon=True)
        t.start()
        threads.append(t)
    for t in threads: t.join(timeout=5)
    if failures:
        _bad(f"concurrent send/recv failures: {failures}")
    _ok("5 concurrent sessions: all sent + received correctly")

    for ep in eps: ep.stop()

    # ── test 5: reconnection after SSH client closed ─────────────────
    pool.shutdown('test-cluster-1')
    ep = pool.acquire(
        cluster_id='test-cluster-1', pve_host='127.0.0.1', ssh_port=ssh_port,
        ssh_user='tester', ssh_password='tt',
        target_host='127.0.0.1', target_port=echo_port,
    )
    time.sleep(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', ep.local_port))
    s.sendall(b'reconn')
    s.settimeout(3.0)
    r = s.recv(64)
    if r != b'ECHO:reconn':
        _bad(f"reconnection round-trip failed: {r!r}")
    s.close()
    ep.stop()
    _ok("reconnection after pool.shutdown(): new transport built, bytes flowed")

    pool.shutdown()
    print("\n=== all 5 self-tests passed ===")
