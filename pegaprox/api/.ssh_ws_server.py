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
    
    from urllib.parse import urlparse, parse_qs, unquote
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    session_id = query.get('session', [None])[0]
    prefetched_ip = query.get('ip', [None])[0]  # IP pre-fetched by frontend
    if prefetched_ip:
        prefetched_ip = unquote(prefetched_ip)
        print(f"Frontend provided IP: {prefetched_ip}")
    
    # Match both /shell and /shellws
    match = re.match(r'/api/clusters/([^/]+)/nodes/([^/]+)/shell(?:ws)?', parsed.path)
    if not match:
        print(f"Invalid path: {parsed.path}")
        await websocket.send('{"status":"error","message":"Invalid path"}')
        await websocket.close(1008, "Invalid path")
        return
    
    cluster_id, node = match.groups()
    print(f"Cluster: {cluster_id}, Node: {node}")
    
    # Validate session (just to ensure user is logged in to PegaProx)
    if not session_id:
        print("No session provided")
        await websocket.send('{"status":"error","message":"No session provided"}')
        await websocket.close(1008, "No session")
        return
    
    print(f"Session ID received: {session_id[:20]}..." if len(session_id) > 20 else f"Session ID: {session_id}")
    
    try:
        print(f"Validating session with: {PEGAPROX_URL}/api/auth/validate")
        # Try both cookie and header-based auth
        headers = {'X-Session-ID': session_id}
        r = requests.get(f"{PEGAPROX_URL}/api/auth/validate", 
                        cookies={'session': session_id}, 
                        headers=headers,
                        timeout=5, verify=False)
        print(f"Session validation response: {r.status_code}")
        if r.status_code != 200:
            print(f"Session validation failed: {r.status_code} - {r.text[:100] if r.text else 'no body'}")
            await websocket.send('{"status":"error","message":"Session ungültig - bitte neu einloggen"}')
            await websocket.close(1008, "Invalid session")
            return
        print("Session validation successful")
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
    
    # Get node IP - use pre-fetched IP if available
    node_ip = prefetched_ip if prefetched_ip else None
    cluster_host = None
    
    # Only try API if we don't have a pre-fetched IP
    if not node_ip:
        # Method 1: Try API endpoint
        try:
            print(f"Fetching cluster creds from: {PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}")
            r = requests.get(f"{PEGAPROX_URL}/api/internal/cluster-creds/{cluster_id}", cookies={'session': session_id}, timeout=10, verify=False)
            print(f"Cluster creds response: {r.status_code}")
            if r.status_code == 200:
                creds = r.json()
                cluster_host = creds.get('host')
                node_ips = creds.get('node_ips', {})
                
                # Try exact match first, then case-insensitive
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
                # Try common config locations
                config_paths = [
                    'config/clusters.json',  # Relative to working dir
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
        
        # Use cluster_host as fallback for node_ip
        if not node_ip and cluster_host:
            node_ip = cluster_host
            print(f"Using cluster host as fallback: {cluster_host}")
    
    # If we still don't have an IP, allow manual entry
    allow_manual_ip = False
    if not node_ip:
        print(f"No IP found - allowing manual entry")
        node_ip = ""  # Empty - user must provide
        allow_manual_ip = True
    
    print(f"Final node IP for {node}: {node_ip or '(manual entry required)'}")
    
    # Send need_credentials status - frontend will show login dialog
    await websocket.send(json.dumps({
        'status': 'need_credentials',
        'node': node,
        'ip': node_ip,
        'allowManualIp': allow_manual_ip
    }))
    
    # Wait for credentials from user
    try:
        creds_msg = await asyncio.wait_for(websocket.recv(), timeout=300)  # 5 min timeout
        creds = json.loads(creds_msg)
        ssh_user = creds.get('username', 'root')
        ssh_pass = creds.get('password', '')
        ssh_key = creds.get('privateKey', '')  # SSH private key (PEM format)
        
        # Allow user to override IP (for manual entry)
        user_ip = creds.get('host', '').strip()
        if user_ip:
            node_ip = user_ip
            print(f"Using user-provided IP: {node_ip}")
        
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

async def main():
    ssl_context = None
    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
    
    # Issue #71/#95: empty host = all interfaces (dual-stack IPv4+IPv6)
    ws_host = None if not BIND_HOST else BIND_HOST
    display_host = BIND_HOST or '0.0.0.0'
    try:
        async with websockets.serve(ssh_handler, ws_host, PORT, ssl=ssl_context, ping_interval=30, ping_timeout=10):
            print(f"SSH WebSocket server ready on {display_host}:{PORT}")
            await asyncio.Future()
    except OSError as e:
        if ':' in str(display_host):
            print(f"SSH WebSocket: IPv6 bind failed ({e}), falling back to 0.0.0.0")
            async with websockets.serve(ssh_handler, '0.0.0.0', PORT, ssl=ssl_context, ping_interval=30, ping_timeout=10):
                print(f"SSH WebSocket server ready on 0.0.0.0:{PORT}")
                await asyncio.Future()
        else:
            raise

if __name__ == '__main__':
    asyncio.run(main())
