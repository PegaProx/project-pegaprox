#!/usr/bin/env python3
"""Standalone SSH WebSocket Server - runs without gevent"""
import asyncio
import ssl
import json
import re
import sys
import os
import warnings
warnings.filterwarnings('ignore')

PORT = int(os.environ.get('SSH_WS_PORT', 5002))
BIND_HOST = os.environ.get('SSH_WS_HOST', '0.0.0.0')
SSL_CERT = os.environ.get('SSH_WS_SSL_CERT', '')
SSL_KEY = os.environ.get('SSH_WS_SSL_KEY', '')
PEGAPROX_URL = os.environ.get('PEGAPROX_URL', 'http://127.0.0.1:5000')

try:
    import websockets
    import paramiko
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError as e:
    print(f"Missing library: {e}")
    sys.exit(1)

async def ssh_handler(websocket):
    """SSH WebSocket handler with user credential prompt and SSH key support
    
    MK: Supports both password and SSH key authentication
    Frontend can pre-fetch the IP and pass it as query parameter
    """
    path = websocket.request.path if hasattr(websocket, 'request') else websocket.path
    print(f"SSH WebSocket connection: {path}")
    
    from urllib.parse import urlparse, parse_qs, unquote, quote_plus
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    ws_token = query.get('token', [None])[0]
    session_id = query.get('session', [None])[0]  # LW: backwards compat
    prefetched_ip = query.get('ip', [None])[0]  # IP pre-fetched by frontend
    if prefetched_ip:
        prefetched_ip = unquote(prefetched_ip)
        print(f"Frontend provided IP: {prefetched_ip}")

    # NS May 2026 — accept both shell and termproxy paths.
    # termproxy: /api/clusters/<cid>/vms/<node>/<vm_type>/<vmid>/termwebsocket
    #            with ?ticket=, ?port=, ?user=, ?host= from the frontend.
    m_term = re.match(r'/api/clusters/([^/]+)/vms/([^/]+)/(qemu|lxc)/([0-9]+)/termwebsocket', parsed.path)
    if m_term:
        await termproxy_handler(websocket, query, m_term, ws_token, session_id)
        return

    # Match both /shell and /shellws
    match = re.match(r'/api/clusters/([^/]+)/nodes/([^/]+)/shell(?:ws)?', parsed.path)
    if not match:
        print(f"Invalid path: {parsed.path}")
        await websocket.send('{"status":"error","message":"Invalid path"}')
        await websocket.close(1008, "Invalid path")
        return

    cluster_id, node = match.groups()
    print(f"Cluster: {cluster_id}, Node: {node}")

    # NS: Mar 2026 - prefer WS token auth (single-use, doesn't leak session)
    auth_token = ws_token or session_id
    if not auth_token:
        print("No token or session provided")
        await websocket.send('{"status":"error","message":"No auth token provided"}')
        await websocket.close(1008, "No auth")
        return

    # Validate via main server
    try:
        if ws_token:
            # MK May 2026 (CodeAnt CWE-285) - bind validate to this cluster so the
            # main server cross-checks RBAC for *this* cluster, not just session-alive.
            validate_url = f"{PEGAPROX_URL}/api/ws/token/validate?token={ws_token}&cluster_id={quote_plus(cluster_id)}"
            print(f"Validating WS token (cluster={cluster_id})...")
        else:
            validate_url = f"{PEGAPROX_URL}/api/auth/validate"
            print("Validating session (legacy)...")

        headers = {'X-Session-ID': session_id} if session_id else {}
        cookies = {'session': session_id} if session_id else {}
        r = requests.get(validate_url, cookies=cookies, headers=headers, timeout=5, verify=False)

        if r.status_code == 403:
            print(f"Auth failed: 403 (no access to cluster {cluster_id})")
            await websocket.send(json.dumps({'status': 'error', 'message': f'No access to cluster {cluster_id}'}))
            await websocket.close(1008, "Forbidden")
            return
        if r.status_code != 200:
            print(f"Auth failed: {r.status_code}")
            await websocket.send('{"status":"error","message":"Session ungültig - bitte neu einloggen"}')
            await websocket.close(1008, "Invalid auth")
            return
        print("Auth successful")
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error to main server: {e}")
        # NS Feb 2026 - never skip auth, even if main server is unreachable
        await websocket.send('{"status":"error","message":"Authentifizierung fehlgeschlagen - Server nicht erreichbar"}')
        await websocket.close(1011, "Auth server unreachable")
        return
    except Exception as e:
        print(f"Auth error: {e}")
        await websocket.send('{"status":"error","message":"Authentifizierungsfehler"}')
        await websocket.close(1011, "Auth error")
        return

    # MK May 2026 (CodeAnt CWE-918) - resolve cluster-creds *always*, so the
    # prefetched ?ip= and the user-supplied creds.host can be gated against the
    # cluster's known node IPs. Previously prefetched_ip skipped the lookup.
    node_ip = None
    cluster_host = None
    node_ips = {}

    # Method 1: Try API endpoint (unconditional)
    try:
        print(f"Fetching cluster creds from: {PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}")
        r = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}", cookies={'session': session_id}, timeout=10, verify=False)
        print(f"Cluster creds response: {r.status_code}")
        if r.status_code == 200:
            creds = r.json()
            cluster_host = creds.get('host')
            node_ips = creds.get('node_ips', {})
            node_ip = node_ips.get(node) or node_ips.get(node.lower())
            print(f"Got node_ips: {node_ips}, looking for: {node}, found: {node_ip}, cluster_host: {cluster_host}")
        else:
            print(f"Cluster creds failed: {r.status_code} - {r.text[:200] if r.text else 'no body'}")
    except Exception as e:
        print(f"Could not get node IP from API: {e}")

    # Method 2: Fallback - read directly from clusters config file
    if not cluster_host:
        try:
            import os
            config_paths = [
                'config/clusters.json',
                './config/clusters.json',
                '/home/admin_321/pegaprox/config/clusters.json',
                '/home/admin_321/pegaprox/data/clusters.json',
                './data/clusters.json',
                os.path.expanduser('~/.pegaprox/clusters.json'),
                '/var/lib/pegaprox/clusters.json'
            ]
            print(f"Trying config file fallback, cwd={os.getcwd()}")
            for config_path in config_paths:
                if os.path.exists(config_path):
                    print(f"Found config at: {config_path}")
                    with open(config_path, 'r') as f:
                        clusters = json.load(f)
                    if cluster_id in clusters:
                        cluster_host = clusters[cluster_id].get('host')
                        print(f"Got cluster_host from config file: {cluster_host}")
                        break
                    else:
                        print(f"Cluster {cluster_id} not in config, available: {list(clusters.keys())}")
        except Exception as e:
            print(f"Config file fallback failed: {e}")

    # cluster_host fallback for node_ip
    if not node_ip and cluster_host:
        node_ip = cluster_host
        print(f"Using cluster host as fallback: {cluster_host}")

    # MK May 2026 (CodeAnt CWE-918) - build the SSH allow-list. prefetched_ip from
    # URL and user-supplied creds.host below must both be in this set; otherwise
    # an authenticated user could turn PegaProx into an SSH jump host for any
    # internal IP. Set comes from server-side resolution only.
    allowed_hosts = set()
    if cluster_host:
        allowed_hosts.add(cluster_host)
    allowed_hosts.update(v for v in (node_ips or {}).values() if v)

    if prefetched_ip:
        if prefetched_ip in allowed_hosts:
            node_ip = prefetched_ip
            print(f"Using prefetched IP (allow-list match): {node_ip}")
        else:
            print(f"REJECT prefetched ?ip={prefetched_ip!r} not in {sorted(allowed_hosts)}")
            await websocket.send(json.dumps({
                'status': 'error',
                'message': f"Prefetched IP {prefetched_ip!r} is not a known node of cluster {cluster_id}."
            }))
            await websocket.close(1008, "prefetched ip not allowed")
            return

    # If we still don't have an IP, allow manual entry (but allow-list still applies)
    allow_manual_ip = False
    if not node_ip:
        print(f"No IP found - allowing manual entry")
        node_ip = ""  # Empty - user must provide
        allow_manual_ip = True

    print(f"Final node IP for {node}: {node_ip or '(manual entry required)'}")
    print(f"Allow-list for host override: {sorted(allowed_hosts) or '(empty - no manual override permitted)'}")

    # Send need_credentials status - frontend will show login dialog
    await websocket.send(json.dumps({
        'status': 'need_credentials',
        'node': node,
        'ip': node_ip,
        'allowManualIp': allow_manual_ip
    }))

    # Wait for credentials from user
    try:
        creds_msg = await asyncio.wait_for(websocket.recv(), timeout=300)
        creds = json.loads(creds_msg)
        ssh_user = creds.get('username', 'root')
        ssh_pass = creds.get('password', '')
        ssh_key = creds.get('privateKey', '')

        # MK May 2026 (CodeAnt CWE-918) - host override is gated by allow_hosts.
        # Empty set rejects all overrides (no-resolved-cluster case).
        user_ip = creds.get('host', '').strip()
        if user_ip:
            if user_ip not in allowed_hosts:
                print(f"REJECT user host override: {user_ip!r} not in {sorted(allowed_hosts)}")
                await websocket.send(json.dumps({
                    'status': 'error',
                    'message': f"Host {user_ip!r} is not a known node of cluster {cluster_id}. Manual override blocked."
                }))
                await websocket.close(1008, "host not allowed")
                return
            node_ip = user_ip
            print(f"Using user-provided IP (allow-list match): {node_ip}")

        if not node_ip:
            await websocket.send('{"status":"error","message":"Host/IP address required"}')
            return
        
        if not ssh_pass and not ssh_key:
            await websocket.send('{"status":"error","message":"Password or SSH key required"}')
            return
            
    except asyncio.TimeoutError:
        await websocket.send('{"status":"error","message":"Login timeout"}')
        await websocket.close(1008, "Timeout")
        return
    except Exception as e:
        print(f"Credentials receive error: {e}")
        await websocket.send('{"status":"error","message":"Failed to receive credentials"}')
        return
    
    # Send connecting status
    await websocket.send('{"status":"connecting"}')
    
    # Connect SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
    
    try:
        print(f"Connecting SSH to {ssh_user}@{node_ip}...")
        
        # Try SSH key authentication first if provided
        if ssh_key:
            try:
                import io
                # Parse the private key
                key_file = io.StringIO(ssh_key)
                
                # Try different key types
                pkey = None
                for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, getattr(paramiko, 'DSSKey', None)]:
                    if key_class is None:
                        continue
                    try:
                        key_file.seek(0)
                        pkey = key_class.from_private_key(key_file, password=ssh_pass if ssh_pass else None)
                        break
                    except:
                        continue
                
                if pkey:
                    print(f"Using SSH key authentication")
                    ssh.connect(node_ip, port=22, username=ssh_user, pkey=pkey, timeout=10, look_for_keys=False, allow_agent=False)
                else:
                    raise Exception("Could not parse SSH key - unsupported format")
                    
            except Exception as key_error:
                print(f"SSH key auth failed: {key_error}")
                await websocket.send(f'{{"status":"error","message":"SSH key error: {str(key_error)}"}}')
                return
        else:
            # Password authentication
            ssh.connect(node_ip, port=22, username=ssh_user, password=ssh_pass, timeout=10, look_for_keys=False, allow_agent=False)
        
        channel = ssh.invoke_shell(term='xterm-256color', width=120, height=40)
        channel.settimeout(0.1)

        print(f"SSH connected: {cluster_id}/{node}")

        # Send connected status - frontend will clear terminal
        await websocket.send('{"status":"connected"}')
        
        async def ssh_to_ws():
            while True:
                try:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if data:
                            await websocket.send(data.decode('utf-8', errors='replace'))
                    await asyncio.sleep(0.01)
                except:
                    break
        
        async def ws_to_ssh():
            try:
                async for message in websocket:
                    if isinstance(message, str):
                        if message.startswith('{"type":"resize"'):
                            try:
                                data = json.loads(message)
                                if data.get('type') == 'resize':
                                    channel.resize_pty(width=data.get('cols', 120), height=data.get('rows', 40))
                            except:
                                pass
                        elif message.startswith('{'):
                            # Ignore other JSON messages (like old credential format)
                            pass
                        else:
                            channel.send(message)
                    else:
                        channel.send(message)
            except:
                pass
        
        await asyncio.gather(ssh_to_ws(), ws_to_ssh(), return_exceptions=True)
    except paramiko.AuthenticationException as e:
        print(f"SSH auth failed: {e}")
        await websocket.send(f'\r\n\x1b[31mSSH Authentication Failed\x1b[0m\r\nCheck cluster credentials.\r\n')
    except Exception as e:
        print(f"SSH error: {e}")
        try:
            await websocket.send(f"\r\n\x1b[31mSSH Error: {e}\x1b[0m\r\n")
        except:
            pass
    finally:
        try:
            ssh.close()
        except:
            pass
        print(f"SSH disconnected: {cluster_id}/{node}")


# NS May 2026 — Proxmox termproxy proxy.
# Frontend has already POSTed /termproxy on the main app and got a ticket.
# It sends the ticket+port+host+user as query params on the WS open.
# We connect to PVE's vncwebsocket with that ticket, send the
# `user:ticket\n` handshake, wait for "OK", then proxy bytes both ways.
# No SSH, no second login — the cluster auth happens server-side at the
# /termproxy POST step.
async def termproxy_handler(client_ws, query, m_term, ws_token, session_id):
    from urllib.parse import unquote, quote_plus
    cluster_id, node, vm_type, vmid_str = m_term.groups()
    print(f"[TERMPROXY] {vm_type}/{vmid_str} on {node} cluster={cluster_id}")

    auth_token = ws_token or session_id
    if not auth_token:
        await client_ws.send('{"status":"error","message":"No auth token"}')
        await client_ws.close(1008, "No auth")
        return

    # Validate via main server (same as shell + cluster-scope check)
    try:
        if ws_token:
            # MK May 2026 (CodeAnt CWE-285) - cluster-scoped validate.
            validate_url = f"{PEGAPROX_URL}/api/ws/token/validate?token={ws_token}&cluster_id={quote_plus(cluster_id)}"
        else:
            validate_url = f"{PEGAPROX_URL}/api/auth/validate"
        headers = {'X-Session-ID': session_id} if session_id else {}
        cookies = {'session': session_id} if session_id else {}
        r = requests.get(validate_url, cookies=cookies, headers=headers, timeout=5, verify=False)
        if r.status_code == 403:
            await client_ws.send(json.dumps({'status': 'error', 'message': f'No access to cluster {cluster_id}'}))
            await client_ws.close(1008, "Forbidden")
            return
        if r.status_code != 200:
            await client_ws.send('{"status":"error","message":"Invalid session"}')
            await client_ws.close(1008, "auth")
            return
    except Exception as e:
        print(f"[TERMPROXY] auth validate failed: {e}")
        await client_ws.send('{"status":"error","message":"Auth server unreachable"}')
        await client_ws.close(1011, "auth")
        return

    # Frontend gave us the termproxy ticket+port already (via POST /termproxy)
    # plus the PVE session auth_ticket (used as PVEAuthCookie header).
    pve_ticket = query.get('ticket', [None])[0]
    pve_port = query.get('port', [None])[0]
    pve_host = query.get('host', [None])[0]
    pve_user = query.get('user', [None])[0]
    pve_auth = query.get('auth_ticket', [None])[0]
    if not (pve_ticket and pve_port and pve_host and pve_user and pve_auth):
        print(f"[TERMPROXY] missing query params; got: ticket={bool(pve_ticket)} port={pve_port} host={pve_host} user={pve_user} auth={bool(pve_auth)}")
        await client_ws.send('{"status":"error","message":"Missing termproxy params"}')
        await client_ws.close(1008, "params")
        return

    pve_ticket = unquote(pve_ticket)
    pve_user = unquote(pve_user)
    pve_host = unquote(pve_host)
    pve_auth = unquote(pve_auth)

    # MK May 2026 (CodeAnt CWE-918) - same SSRF gate as the shell path. pve_host is
    # otherwise an unrestricted user-input that gets embedded in the wss:// URL.
    # Port is hardcoded 8006 so the surface was narrower than the shell SSRF, but
    # an authenticated user could still probe :8006 on arbitrary internal hosts.
    allowed_hosts = set()
    try:
        cookies = {'session': session_id} if session_id else {}
        cr = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}",
                          cookies=cookies, timeout=10, verify=False)
        if cr.status_code == 200:
            cr_data = cr.json() or {}
            if cr_data.get('host'):
                allowed_hosts.add(cr_data['host'])
            allowed_hosts.update(v for v in (cr_data.get('node_ips') or {}).values() if v)
        else:
            print(f"[TERMPROXY] cluster-creds non-200 ({cr.status_code}); allow-list empty -> rejecting host")
    except Exception as e:
        print(f"[TERMPROXY] cluster-creds fetch failed: {e}; allow-list empty -> rejecting host")

    if pve_host not in allowed_hosts:
        print(f"[TERMPROXY] REJECT host {pve_host!r} (not in {sorted(allowed_hosts)})")
        await client_ws.send(json.dumps({
            'status': 'error',
            'message': f"Host {pve_host!r} is not a known node of cluster {cluster_id}."
        }))
        await client_ws.close(1008, "host not allowed")
        return

    # Connect to PVE WS — Cookie uses session auth ticket; URL uses termproxy ticket.
    pve_path = f"/api2/json/nodes/{node}/{vm_type}/{vmid_str}/vncwebsocket?port={pve_port}&vncticket={quote_plus(pve_ticket)}"
    pve_url = f"wss://{pve_host}:8006{pve_path}"
    print(f"[TERMPROXY] connecting to PVE: {pve_url}")
    pve_ssl = ssl.create_default_context()
    pve_ssl.check_hostname = False
    pve_ssl.verify_mode = ssl.CERT_NONE
    try:
        pve_ws = await websockets.connect(
            pve_url,
            additional_headers={'Cookie': f'PVEAuthCookie={pve_auth}'},
            ssl=pve_ssl,
            open_timeout=10,
        )
    except Exception as e:
        print(f"[TERMPROXY] PVE WS connect failed: {type(e).__name__}: {e}")
        await client_ws.send(f'{{"status":"error","message":"PVE WS connect failed: {type(e).__name__}"}}')
        await client_ws.close(1011, "pve")
        return

    # Send PVE auth handshake: user:ticket\n
    try:
        await pve_ws.send(f"{pve_user}:{pve_ticket}\n")
        first = await asyncio.wait_for(pve_ws.recv(), timeout=5.0)
        first_str = first.decode('utf-8', errors='replace') if isinstance(first, (bytes, bytearray)) else (first or '')
        if not first_str.startswith('OK'):
            print(f"[TERMPROXY] PVE rejected handshake: {first_str!r}")
            await client_ws.send(f'{{"status":"error","message":"PVE rejected: {first_str[:80]!r}"}}')
            await pve_ws.close()
            await client_ws.close(1011, "pve-auth")
            return
        print(f"[TERMPROXY] PVE handshake OK")
    except Exception as e:
        print(f"[TERMPROXY] handshake error: {type(e).__name__}: {e}")
        await client_ws.send(f'{{"status":"error","message":"handshake error: {type(e).__name__}"}}')
        try: await pve_ws.close()
        except: pass
        await client_ws.close(1011, "handshake")
        return

    await client_ws.send('{"status":"connected"}')

    # Bidirectional proxy
    async def pve_to_client():
        try:
            async for msg in pve_ws:
                # PVE termproxy sends raw bytes (TTY output)
                if isinstance(msg, (bytes, bytearray)):
                    await client_ws.send(msg.decode('utf-8', errors='replace'))
                else:
                    await client_ws.send(msg)
        except Exception as e:
            print(f"[TERMPROXY] PVE→client: {type(e).__name__}: {e}")

    async def client_to_pve():
        try:
            async for msg in client_ws:
                if isinstance(msg, str):
                    # Resize protocol: JSON {type:'resize', cols, rows}
                    if msg.startswith('{'):
                        try:
                            j = json.loads(msg)
                            if j.get('type') == 'resize':
                                cols = int(j.get('cols', 80))
                                rows = int(j.get('rows', 24))
                                await pve_ws.send(f"1:{cols}:{rows}:")
                                continue
                        except Exception:
                            pass
                    payload_len = len(msg.encode('utf-8'))
                    await pve_ws.send(f"0:{payload_len}:{msg}")
                else:
                    try: text = msg.decode('utf-8')
                    except Exception: text = msg.decode('latin-1', errors='replace')
                    await pve_ws.send(f"0:{len(msg)}:{text}")
        except Exception as e:
            print(f"[TERMPROXY] client→PVE: {type(e).__name__}: {e}")

    try:
        await asyncio.gather(pve_to_client(), client_to_pve(), return_exceptions=True)
    finally:
        try: await pve_ws.close()
        except: pass
        print(f"[TERMPROXY] session ended {vm_type}/{vmid_str}")


async def main():
    ssl_context = None
    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    # Issue #71/#95: empty host = all interfaces (dual-stack IPv4+IPv6)
    ws_host = None if not BIND_HOST else BIND_HOST
    display_host = BIND_HOST or '0.0.0.0'
    # NS May 2026 (#388): wire the lenient_process_request hook so PVE 9.1.x
    # hosts (and any middlebox that strips the Upgrade token from Connection)
    # don't trigger InvalidUpgrade at SSH WS handshake. Was only on VNC before.
    # crcro on issue #388 reported the exact SSH-WS InvalidUpgrade trace this fixes.
    _lpr_ssh = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from pegaprox.utils.ws_lenient import lenient_process_request as _lpr_ssh
    except Exception as _e:
        print(f"[SSH-WS] WARNING: lenient_process_request not importable ({_e}) — strict handshake only")
    serve_kwargs = {'ssl': ssl_context, 'ping_interval': 30, 'ping_timeout': 10}
    if _lpr_ssh is not None:
        serve_kwargs['process_request'] = _lpr_ssh
    try:
        async with websockets.serve(ssh_handler, ws_host, PORT, **serve_kwargs):
            print(f"SSH WebSocket server ready on {display_host}:{PORT} (lenient-hook={_lpr_ssh is not None})")
            await asyncio.Future()
    except OSError as e:
        if ':' in str(display_host):
            print(f"SSH WebSocket: IPv6 bind failed ({e}), falling back to 0.0.0.0")
            async with websockets.serve(ssh_handler, '0.0.0.0', PORT, **serve_kwargs):
                print(f"SSH WebSocket server ready on 0.0.0.0:{PORT}")
                await asyncio.Future()
        else:
            raise

if __name__ == '__main__':
    asyncio.run(main())
