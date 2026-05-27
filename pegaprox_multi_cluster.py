#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PegaProx Server - Cluster Management Backend for Proxmox VE
Version: 0.7.0 Beta

Copyright (C) 2025-2026 PegaProx Team

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

═══════════════════════════════════════════════════════════════════════════════

Dev Team:
  NS - Nico Schmidt (Lead)
  MK - Marcus Kellermann (Backend)
  LW - Laura Weber (Frontend, but helps here too sometimes)

Contributors:
  Florian Paul Azim Hoberg @gyptazy
  Alexandre Derumier @aderumier (Performance chart styling)

Credits & Acknowledgments:
- ProxLB by gyptazy (https://github.com/gyptazy/ProxLB)
- ProxSnap by gyptazy (https://github.com/gyptazy/ProxSnap)

═══════════════════════════════════════════════════════════════════════════════

v0.7.0: Code split from single 51k-line file into pegaprox/ package.
DONE: CODE SPLITTING - NS feb 2026
      -> split into: pegaprox/{api/, core/, models/, utils/, background/}
DONE: Archive-based update mechanism - NS feb 2026

═══════════════════════════════════════════════════════════════════════════════
"""

# CRITICAL: Gevent MUST be first!! dont move this!! - NS
import os
import sys

USE_GEVENT = os.environ.get('PEGAPROX_NO_GEVENT', '').lower() not in ('1', 'true', 'yes')

if USE_GEVENT:
    try:
        from gevent import monkey
        monkey.patch_all()
        print("Gevent monkey-patching applied")
    except ImportError:
        pass

import aikido_zen
aikido_zen.protect()

import warnings
warnings.filterwarnings('ignore', message='coroutine.*was never awaited')
warnings.filterwarnings('ignore', category=RuntimeWarning, module='asyncio')

# NS May 2026 — disable PerMessageDeflate in simple-websocket. The library
# hard-codes the extension on AcceptConnection which causes it to send
# RSV1=1 frames even when negotiation didn't take place, making strict
# RFC-6455 clients (Node ws, browsers in some setups) reject every frame
# with "RSV1 must be clear". We patch the AcceptConnection call to pass
# an empty extensions list so framing stays vanilla.
def _disable_simple_websocket_deflate():
    try:
        import simple_websocket.ws as _swws
        from wsproto.events import AcceptConnection as _Accept
        _orig = _swws.Server._handle_events
        # Replace the hard-coded extension with no extensions on the
        # AcceptConnection emission. We monkey-patch by overriding the
        # AcceptConnection class so any kw passed gets stripped.
        class _NoExtAccept(_Accept):
            def __init__(self, *a, **kw):
                kw.pop('extensions', None)
                super().__init__(*a, **kw)
        _swws.AcceptConnection = _NoExtAccept
        print('[ws-patch] simple-websocket PerMessageDeflate disabled')
    except Exception as _e:
        print(f'[ws-patch] could not disable deflate: {_e}')

_disable_simple_websocket_deflate()


def print_system_requirements():
    """Print recommended system requirements"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    PegaProx System Requirements Guide                         ║
║                           Version 0.7.0 Beta - Feb 2026                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Clusters │ Concurrent │  CPU    │  RAM   │  Disk  │  Notes                  ║
║           │   Users    │ Cores   │        │        │                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1-5      │  1-5       │ 1 core  │  1 GB  │  1 GB  │  Testing/Home Lab       ║
║  5-20     │  5-10      │ 2 cores │  2 GB  │  5 GB  │  Small Production       ║
║  20-50    │  10-25     │ 4 cores │  4 GB  │ 10 GB  │  Medium Production      ║
║  50-100   │  25-50     │ 4 cores │  8 GB  │ 20 GB  │  Large Production       ║
║  100-200  │  50-100    │ 8 cores │ 16 GB  │ 50 GB  │  Enterprise             ║
║  200+     │  100+      │ 16 cores│ 32 GB  │100 GB  │  Large Enterprise       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Performance Tips:                                                            ║
║  • Install gevent: pip install gevent (2-3x better concurrency)              ║
║  • Set workers: PEGAPROX_WORKERS=<cpu_count>                                 ║
║  • Use SSD for config storage (faster JSON read/write)                       ║
║  • Place behind nginx/haproxy for SSL termination & load balancing           ║
║  • Enable gzip compression in reverse proxy                                  ║
║  • Use Redis for session storage in multi-node setups (future)               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Network Requirements:                                                        ║
║  • Port 5000: Main API & Web UI (configurable via PEGAPROX_PORT)             ║
║  • Port 5001: VNC WebSocket (noVNC console) - auto: main_port + 1            ║
║  • Port 5002: SSH WebSocket (Node shell) - auto: main_port + 2               ║
║  • HTTPS recommended (--ssl-cert/--ssl-key or auto-generated)                ║
║  • Access to all Proxmox nodes on port 8006                                  ║
║  • Self-signed certs: Users must accept cert on ports 5001/5002 separately   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Dependencies:                                                                ║
║  • Python 3.8+ (3.10+ recommended)                                           ║
║  • Flask, flask-sock, requests, urllib3                                      ║
║  • paramiko (for SSH shell)                                                  ║
║  • websockets (for VNC and SSH WebSocket servers)                            ║
║  • gevent (optional, for better performance)                                 ║
║  • websocket-client (for Proxmox VNC proxy)                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def download_static_files():
    """Download all required static files for offline operation."""
    # Import from the package
    from pegaprox.app import download_static_files as _download
    return _download()


if __name__ == '__main__':
    if '--requirements' in sys.argv:
        print_system_requirements()
    elif '--download-static' in sys.argv:
        download_static_files()
    # MK May 2026 — DB-migration + key-management CLI subcommands.
    # These short-circuit the normal server startup so an admin can run
    # them on a stopped instance without --debug spinning up gevent etc.
    elif '--migrate-db' in sys.argv:
        from pegaprox.cli.migrate_db import main as _migrate_main
        sub_args = [a for a in sys.argv[1:] if a != '--migrate-db']
        sys.exit(_migrate_main(sub_args))
    elif '--print-key' in sys.argv:
        # Print the resolved master key (base64) — for use by `systemd-creds
        # encrypt`, secret-manager handoff, or `.env` setup.  Output goes to
        # stdout only; stderr gets a one-line provenance note.
        from pegaprox.core.keystore import load_master_key
        mk = load_master_key()
        sys.stderr.write(f"[KEYSTORE] master key source: {mk.source}"
                          f"{' (' + mk.source_path + ')' if mk.source_path else ''}\n")
        sys.stdout.buffer.write(mk.key_b64)
        sys.stdout.flush()
        sys.exit(0)
    elif '--keystore-status' in sys.argv:
        # Human-readable status of the current key + DB-backend.
        import json as _json
        from pegaprox.core.keystore import health_status as _ks_health
        from pegaprox.core.dbcrypto import backend_status as _db_status
        print(_json.dumps({'keystore': _ks_health(), 'db': _db_status()},
                           indent=2))
        sys.exit(0)
    elif '--help' in sys.argv or '-h' in sys.argv:
        print("""
PegaProx Server

Usage:
  python pegaprox_multi_cluster.py [options]

Options:
  --debug           verbose logging
  --requirements    show requirements
  --download-static download js libs for offline mode
  --migrate-db      migrate plain SQLite DB to SQLCipher (see --migrate-db --help)
  --print-key       print the resolved master key (base64) to stdout
  --keystore-status JSON dump of key-source + DB-backend status
  --help, -h        this message

Env vars:
  PEGAPROX_DB_KEY            master key (urlsafe-base64 or hex)
  PEGAPROX_KEY_FILE          path to key file (overrides default lookup chain)
  CREDENTIALS_DIRECTORY      systemd LoadCredentialEncrypted directory
  PEGAPROX_ALLOWED_ORIGINS   cors origins
  PEGAPROX_MAX_REQUEST_SIZE  max API request size (default 10MB)
  PEGAPROX_MAX_UPLOAD_SIZE   max file upload size (default 4GB)
  PEGAPROX_HTTP_PORT         http port for redirect (default 80)
        """)
    else:
        debug_mode = '--debug' in sys.argv
        try:
            from pegaprox.app import main
        except ImportError as e:
            # NS: feb 2026 - distinguish missing package from missing dependencies
            script_dir = os.path.dirname(os.path.abspath(__file__))
            pkg_dir = os.path.join(script_dir, 'pegaprox')
            venv_python = os.path.join(script_dir, 'venv', 'bin', 'python3')
            venv_python2 = os.path.join(script_dir, 'venv', 'bin', 'python')

            if not os.path.isdir(pkg_dir) or not os.path.isfile(os.path.join(pkg_dir, '__init__.py')):
                print("\n  pegaprox/ package not found - incomplete update?")
                print("  Run ./update.sh to finish the update.\n")
            elif os.path.exists(venv_python) or os.path.exists(venv_python2):
                venv_bin = venv_python if os.path.exists(venv_python) else venv_python2
                print(f"\n  Missing dependency: {e}")
                print(f"\n  A virtual environment exists. Use it to start PegaProx:")
                print(f"    {venv_bin} {os.path.abspath(__file__)}")
                print(f"\n  Or via systemd:")
                print(f"    systemctl start pegaprox\n")
            else:
                print(f"\n  Missing dependency: {e}")
                print(f"\n  Install requirements first:")
                print(f"    pip install -r requirements.txt")
                print(f"\n  Or create a venv:")
                print(f"    python3 -m venv {os.path.join(script_dir, 'venv')}")
                print(f"    {venv_python} -m pip install -r requirements.txt")
                print(f"    {venv_python} {os.path.abspath(__file__)}\n")
            sys.exit(1)
        main(debug_mode=debug_mode)
