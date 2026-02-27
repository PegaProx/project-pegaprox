# -*- coding: utf-8 -*-
"""
PegaProx Flask App Factory - Layer 8
Creates and configures the Flask application.
"""

import os
import sys
import time
import logging
import threading
import signal
import gc
import multiprocessing
import ssl
import socket

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sock import Sock
from flask_compress import Compress

from pegaprox.constants import (
    PEGAPROX_VERSION, PEGAPROX_BUILD,
    SESSION_TIMEOUT, SSL_CERT_FILE, SSL_KEY_FILE,
    API_RATE_LIMIT, API_RATE_WINDOW, SSH_MAX_CONCURRENT,
)
from pegaprox import globals as g
from pegaprox.api import register_blueprints


def get_allowed_origins():
    """Get list of allowed CORS origins (dynamic for Open Source)"""
    origins = set()

    # 1. Environment variable origins (highest priority)
    if g._cors_origins_env:
        for origin in g._cors_origins_env.split(','):
            origin = origin.strip()
            if origin and origin != '*':
                origins.add(origin)

    # 2. Auto-detected origins from successful logins
    origins.update(g._auto_allowed_origins)

    # 3. If nothing configured, allow requests without Origin header (same-origin)
    # This is safe because browsers always send Origin header for cross-origin requests
    if not origins:
        return None  # None = no CORS headers = same-origin only

    return list(origins)


def add_allowed_origin(origin: str):
    """Add an origin to the auto-allowed list (called on successful login)"""
    if origin and origin.startswith(('http://', 'https://')) and origin != '*':
        g._auto_allowed_origins.add(origin)
        logging.info(f"Auto-allowed CORS origin: {origin}")


def create_app():
    """Flask application factory."""
    # root_path must point to the project root (parent of pegaprox/)
    # so that send_from_directory('web', ...) and other relative paths work
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__, root_path=project_root)

    # CORS Configuration - NS: Feb 2026 - only enable if origins are explicitly set
    if g._cors_origins_env:
        allowed_origins = [o.strip() for o in g._cors_origins_env.split(',') if o.strip() and o.strip() != '*']
        if allowed_origins:
            CORS(app, supports_credentials=True, resources={
                r"/api/*": {
                    "origins": allowed_origins,
                    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                    "allow_headers": ["Content-Type", "Authorization", "X-Username", "X-Session-Id"],
                    "expose_headers": ["Content-Type"],
                    "supports_credentials": True
                }
            })
    # else: no CORS init = browser same-origin policy applies (safest default)

    # Gzip compression
    app.config['COMPRESS_MIMETYPES'] = [
        'text/html', 'text/css', 'text/xml', 'text/plain',
        'application/json', 'application/javascript', 'application/xml'
    ]
    app.config['COMPRESS_LEVEL'] = 6
    app.config['COMPRESS_MIN_SIZE'] = 500
    Compress(app)

    # Max request size - NS: Feb 2026 - separate limit for file uploads (#82)
    _default_max = int(os.environ.get('PEGAPROX_MAX_REQUEST_SIZE', 10 * 1024 * 1024))  # 10 MB default for API
    _upload_max = int(os.environ.get('PEGAPROX_MAX_UPLOAD_SIZE', 4 * 1024 * 1024 * 1024))  # 4 GB for uploads
    app.config['MAX_CONTENT_LENGTH'] = _upload_max  # set high, we check per-route below

    # Request validation & rate limiting
    @app.before_request
    def validate_request():
        if request.path.startswith('/static/') or request.path.startswith('/images/'):
            return None
        if request.path.startswith('/ws'):
            return None

        # NS: Feb 2026 - per-route size limits: uploads get the big limit, everything else 10MB
        is_upload = request.path.endswith('/upload')
        if request.content_length:
            max_size = _upload_max if is_upload else _default_max
            if request.content_length > max_size:
                return jsonify({'error': f'Request too large. Max {max_size // (1024*1024)} MB'}), 413
        elif request.method in ('POST', 'PUT', 'PATCH') and not is_upload:
            # NS: Feb 2026 - enforce default limit for requests without Content-Length (e.g. chunked transfer)
            app.config['MAX_CONTENT_LENGTH'] = _default_max

        if request.path.startswith('/api/'):
            skip_paths = ['/api/auth/login', '/api/auth/check', '/api/events', '/api/health', '/api/sse',
                          '/api/vmware/migrations']
            if not any(request.path.startswith(p) for p in skip_paths):
                client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                if client_ip:
                    client_ip = client_ip.split(',')[0].strip()

                if not _check_api_rate_limit(client_ip):
                    logging.warning(f"Rate limit exceeded for {client_ip}")
                    return jsonify({
                        'error': 'Rate limit exceeded. Please slow down.',
                        'retry_after': API_RATE_WINDOW
                    }), 429

        if request.method in ['POST', 'PUT', 'PATCH'] and request.content_length:
            content_type = request.content_type or ''
            allowed_types = ['application/json', 'multipart/form-data', 'application/x-www-form-urlencoded']
            if not any(t in content_type for t in allowed_types):
                if request.content_length > 0:
                    return jsonify({'error': 'Invalid Content-Type'}), 415

        return None

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
                "https://cdn.jsdelivr.net https://cdn.tailwindcss.com "
                "https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' "
                "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' wss: ws: https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers['Content-Security-Policy'] = csp

        if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    # Register all API blueprints
    register_blueprints(app)

    return app


def _check_api_rate_limit(client_ip: str) -> bool:
    """Simple sliding window rate limiter."""
    if API_RATE_LIMIT <= 0:
        return True

    current_time = time.time()

    with g.api_rate_limit_lock:
        if client_ip not in g.api_request_counts:
            g.api_request_counts[client_ip] = {'count': 1, 'window_start': current_time}
            return True

        info = g.api_request_counts[client_ip]

        if current_time - info['window_start'] > API_RATE_WINDOW:
            info['count'] = 1
            info['window_start'] = current_time
            return True

        if info['count'] >= API_RATE_LIMIT:
            return False

        info['count'] += 1
        return True


def download_static_files():
    """Download all required static files for offline operation."""
    import urllib.request
    import re as _re

    print("=" * 60)
    print("PegaProx Static Files Downloader")
    print("=" * 60)
    print()

    static_files = {
        'js': [
            ('react.production.min.js', 'https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js'),
            ('react-dom.production.min.js', 'https://cdn.jsdelivr.net/npm/react-dom@18/umd/react-dom.production.min.js'),
            ('babel.min.js', 'https://cdn.jsdelivr.net/npm/@babel/standalone@7/babel.min.js'),
            ('chart.umd.min.js', 'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js'),
            ('xterm.min.js', 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js'),
            ('xterm-addon-fit.min.js', 'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js'),
        ],
        'css': [
            ('xterm.min.css', 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css'),
        ]
    }

    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)

    ctx = ssl.create_default_context()  # NS: Feb 2026 - use default SSL verification for downloads

    success = 0
    failed = 0

    for subdir, files in static_files.items():
        print(f"Downloading {subdir} files...")
        for filename, url in files:
            dest = f'static/{subdir}/{filename}'
            print(f"  {filename}...", end=' ')
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                    data = response.read()
                with open(dest, 'wb') as f:
                    f.write(data)
                print(f"OK ({len(data):,} bytes)")
                success += 1
            except Exception as e:
                print(f"FAILED: {e}")
                failed += 1

    # Tailwind CSS subset for offline
    print("\nCreating Tailwind CSS subset...")
    tailwind_css = '''/* PegaProx Tailwind Offline CSS */
*, ::before, ::after { box-sizing: border-box; border-width: 0; border-style: solid; }
html { line-height: 1.5; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
body { margin: 0; }
.flex { display: flex; } .grid { display: grid; } .hidden { display: none; } .block { display: block; }
.inline-flex { display: inline-flex; } .flex-col { flex-direction: column; } .flex-1 { flex: 1 1 0%; }
.items-center { align-items: center; } .items-start { align-items: flex-start; }
.justify-center { justify-content: center; } .justify-between { justify-content: space-between; }
.gap-1 { gap: 0.25rem; } .gap-2 { gap: 0.5rem; } .gap-3 { gap: 0.75rem; } .gap-4 { gap: 1rem; } .gap-6 { gap: 1.5rem; }
.p-1 { padding: 0.25rem; } .p-2 { padding: 0.5rem; } .p-3 { padding: 0.75rem; } .p-4 { padding: 1rem; } .p-5 { padding: 1.25rem; } .p-6 { padding: 1.5rem; }
.px-2 { padding-left: 0.5rem; padding-right: 0.5rem; } .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; } .px-4 { padding-left: 1rem; padding-right: 1rem; }
.py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; } .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; } .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
.m-0 { margin: 0; } .mx-auto { margin-left: auto; margin-right: auto; }
.mt-1 { margin-top: 0.25rem; } .mt-2 { margin-top: 0.5rem; } .mt-4 { margin-top: 1rem; }
.mb-1 { margin-bottom: 0.25rem; } .mb-2 { margin-bottom: 0.5rem; } .mb-4 { margin-bottom: 1rem; }
.w-full { width: 100%; } .w-auto { width: auto; } .w-4 { width: 1rem; } .w-5 { width: 1.25rem; } .w-6 { width: 1.5rem; } .w-8 { width: 2rem; }
.h-full { height: 100%; } .h-4 { height: 1rem; } .h-5 { height: 1.25rem; } .h-6 { height: 1.5rem; } .h-8 { height: 2rem; }
.min-h-screen { min-height: 100vh; }
.text-xs { font-size: 0.75rem; } .text-sm { font-size: 0.875rem; } .text-lg { font-size: 1.125rem; } .text-xl { font-size: 1.25rem; } .text-2xl { font-size: 1.5rem; }
.font-medium { font-weight: 500; } .font-semibold { font-weight: 600; } .font-bold { font-weight: 700; }
.font-mono { font-family: ui-monospace, monospace; }
.text-center { text-align: center; } .text-right { text-align: right; }
.uppercase { text-transform: uppercase; } .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rounded { border-radius: 0.25rem; } .rounded-lg { border-radius: 0.5rem; } .rounded-xl { border-radius: 0.75rem; } .rounded-full { border-radius: 9999px; }
.border { border-width: 1px; } .border-2 { border-width: 2px; } .border-t { border-top-width: 1px; } .border-b { border-bottom-width: 1px; }
.opacity-50 { opacity: 0.5; } .opacity-75 { opacity: 0.75; }
.shadow { box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1); } .shadow-lg { box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); }
.overflow-hidden { overflow: hidden; } .overflow-auto { overflow: auto; } .overflow-y-auto { overflow-y: auto; }
.relative { position: relative; } .absolute { position: absolute; } .fixed { position: fixed; }
.inset-0 { top: 0; right: 0; bottom: 0; left: 0; } .top-0 { top: 0; } .right-0 { right: 0; } .bottom-0 { bottom: 0; } .left-0 { left: 0; }
.z-10 { z-index: 10; } .z-50 { z-index: 50; }
.cursor-pointer { cursor: pointer; }
.transition { transition-property: all; transition-duration: 150ms; } .transition-all { transition-property: all; transition-duration: 150ms; }
.animate-spin { animation: spin 1s linear infinite; } .animate-pulse { animation: pulse 2s ease-in-out infinite; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
.grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); } .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); } .grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.col-span-2 { grid-column: span 2 / span 2; } .col-span-3 { grid-column: span 3 / span 3; }
.space-y-2 > :not([hidden]) ~ :not([hidden]) { margin-top: 0.5rem; } .space-y-4 > :not([hidden]) ~ :not([hidden]) { margin-top: 1rem; }
.divide-y > :not([hidden]) ~ :not([hidden]) { border-top-width: 1px; }
@media (min-width: 768px) { .md\\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (min-width: 1280px) { .xl\\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); } .xl\\:col-span-2 { grid-column: span 2 / span 2; } }
'''
    try:
        with open('static/css/tailwind.min.css', 'w') as f:
            f.write(tailwind_css)
        print("  tailwind.min.css... OK")
        success += 1
    except Exception as e:
        print(f"  tailwind.min.css... FAILED: {e}")
        failed += 1

    # Download noVNC for offline VNC console
    print("\nDownloading noVNC for offline VNC console...")
    novnc_base = 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0'
    novnc_files = [
        'core/rfb.js', 'core/display.js', 'core/inflator.js', 'core/deflator.js',
        'core/websock.js', 'core/encodings.js', 'core/des.js', 'core/ra2.js', 'core/base64.js',
        'core/decoders/copyrect.js', 'core/decoders/hextile.js', 'core/decoders/raw.js',
        'core/decoders/rre.js', 'core/decoders/tight.js', 'core/decoders/tightpng.js',
        'core/decoders/zrle.js', 'core/decoders/jpeg.js',
        'core/input/keyboard.js', 'core/input/keysym.js', 'core/input/keysymdef.js',
        'core/input/gesturehandler.js', 'core/input/domkeytable.js', 'core/input/util.js',
        'core/input/vkeys.js', 'core/input/xtscancodes.js', 'core/input/fixedkeys.js',
        'core/util/browser.js', 'core/util/cursor.js', 'core/util/element.js',
        'core/util/events.js', 'core/util/eventtarget.js', 'core/util/int.js',
        'core/util/logging.js', 'core/util/strings.js', 'core/util/md5.js',
        'vendor/pako/lib/zlib/inflate.js', 'vendor/pako/lib/zlib/zstream.js',
        'vendor/pako/lib/zlib/deflate.js', 'vendor/pako/lib/zlib/messages.js',
        'vendor/pako/lib/zlib/trees.js', 'vendor/pako/lib/zlib/adler32.js',
        'vendor/pako/lib/zlib/crc32.js', 'vendor/pako/lib/zlib/inffast.js',
        'vendor/pako/lib/zlib/inftrees.js', 'vendor/pako/lib/utils/common.js',
    ]

    for subdir in ['core', 'core/decoders', 'core/input', 'core/util',
                   'vendor/pako/lib/zlib', 'vendor/pako/lib/utils']:
        os.makedirs(f'static/js/novnc/{subdir}', exist_ok=True)

    novnc_success = 0
    novnc_failed = 0

    for filepath in novnc_files:
        url = f"{novnc_base}/{filepath}"
        dest = f"static/js/novnc/{filepath}"
        filename = filepath.split('/')[-1]
        print(f"  {filename}...", end=' ')
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                content = response.read().decode('utf-8')

            file_dir = '/'.join(filepath.split('/')[:-1])
            pattern = r'''from\s+(['"])(\.{1,2}/[^'"]+)\1'''

            def rewrite_import(match):
                quote = match.group(1)
                rel_path = match.group(2)
                if rel_path.startswith('./'):
                    resolved = f"/static/js/novnc/{file_dir}/{rel_path[2:]}"
                elif rel_path.startswith('../'):
                    parts = file_dir.split('/') if file_dir else []
                    rest = rel_path
                    while rest.startswith('../'):
                        if parts:
                            parts.pop()
                        rest = rest[3:]
                    parent = '/'.join(parts)
                    resolved = f"/static/js/novnc/{parent}/{rest}" if parent else f"/static/js/novnc/{rest}"
                else:
                    resolved = rel_path
                while '//' in resolved:
                    resolved = resolved.replace('//', '/')
                return f"from {quote}{resolved}{quote}"

            content = _re.sub(pattern, rewrite_import, content)

            with open(dest, 'w') as f:
                f.write(content)
            print("OK")
            novnc_success += 1
            success += 1
        except Exception as e:
            print(f"FAILED: {e}")
            novnc_failed += 1
            failed += 1

    rfb_entry = '''// noVNC entry point for PegaProx offline mode
// Auto-generated by --download-static
export { default } from '/static/js/novnc/core/rfb.js';
export * from '/static/js/novnc/core/rfb.js';
'''
    try:
        with open('static/js/novnc/rfb.min.js', 'w') as f:
            f.write(rfb_entry)
        print("  rfb.min.js (entry point)... OK")
        success += 1
    except Exception as e:
        print(f"  rfb.min.js... FAILED: {e}")
        failed += 1

    print(f"\n  noVNC: {novnc_success}/{len(novnc_files)} files downloaded")
    print()
    print("=" * 60)
    print(f"Done: {success} succeeded, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\nAll static files downloaded!")
        print("  PegaProx can run fully offline now (including VNC console)")
    else:
        print("\nSome downloads failed, will use CDN fallback")

    return failed == 0


def main(debug_mode=False):
    """Main entry point - starts PegaProx server."""
    from pegaprox.utils.auth import load_users, load_sessions, create_default_users
    from pegaprox.utils.audit import load_audit_log
    from pegaprox.core.config import load_config
    from pegaprox.core.pbs import load_pbs_servers
    from pegaprox.core.vmware import load_vmware_servers
    from pegaprox.models.tasks import PegaProxConfig
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.background.broadcast import start_broadcast_thread
    from pegaprox.background.alerts import start_alert_thread
    from pegaprox.background.scheduler import start_scheduler_thread
    from pegaprox.background.password_expiry import start_password_expiry_thread
    from pegaprox.background.cross_cluster_lb import start_cross_cluster_lb_thread
    from pegaprox.background.cross_cluster_replication import start_cross_cluster_replication_thread
    from pegaprox.api.helpers import load_server_settings
    from pegaprox.utils.rbac import get_pool_membership_cache
    from pegaprox.constants import AUDIT_RETENTION_DAYS

    # Initialize SSH semaphore
    g.init_ssh_semaphore(SSH_MAX_CONCURRENT)

    # Configure logging
    log_level = logging.DEBUG if debug_mode else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s' if debug_mode else '%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if not debug_mode:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        logging.getLogger('gevent').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)

    if debug_mode:
        print("=" * 50)
        print("DEBUG MODE ENABLED")
        print("=" * 50)

    # Check optional libraries
    print("\nChecking optional libraries...")
    missing_libs = []
    try:
        import websockets
        print("  ✓ websockets (VNC/SSH console)")
    except ImportError:
        missing_libs.append('websockets')
        print("  ✗ websockets - VNC/SSH console will NOT work!")

    try:
        import paramiko
        print("  ✓ paramiko (SSH features)")
    except ImportError:
        missing_libs.append('paramiko')
        print("  ✗ paramiko - SSH features disabled")

    GEVENT_AVAILABLE = False
    try:
        from gevent.pywsgi import WSGIServer
        GEVENT_AVAILABLE = True
        print("  ✓ gevent (high performance)")
    except ImportError:
        print("  ✗ gevent - using Flask dev server (slower)")

    ARGON2_AVAILABLE = False
    try:
        import argon2
        ARGON2_AVAILABLE = True
        print("  ✓ argon2-cffi (secure password hashing)")
    except ImportError:
        print("  ⚠ argon2-cffi - using PBKDF2 fallback")

    if missing_libs:
        print(f"\n  Install missing: pip install {' '.join(missing_libs)}")
    print()

    # Create Flask app
    app = create_app()

    # Init user system
    print("Initializing user system...")
    g.users_db = load_users()
    print(f"Loaded {len(g.users_db)} users")

    # Init audit log
    print("Initializing audit log...")
    load_audit_log()
    print(f"Loaded {len(g.audit_log)} audit entries (retention: {AUDIT_RETENTION_DAYS} days)")

    # Load sessions
    print("Loading sessions...")
    load_sessions()
    print(f"Loaded {len(g.active_sessions)} active sessions")

    # Show default credentials hint
    if len(g.users_db) == 1 and 'pegaprox' in g.users_db:
        print("\n" + "=" * 50)
        print("DEFAULT LOGIN CREDENTIALS:")
        print("  Username: pegaprox")
        print("  Password: admin")
        print("  Please change the password after first login!")
        print("=" * 50 + "\n")

    # Load existing configuration
    config = load_config()

    # Start managers for existing clusters
    for cluster_id, cluster_data in config.items():
        config_obj = PegaProxConfig(cluster_data)
        manager = PegaProxManager(cluster_id, config_obj)
        manager.start()
        g.cluster_managers[cluster_id] = manager
        print(f"Started PegaProx manager for cluster: {cluster_data['name']}")

    # Start background threads
    start_broadcast_thread()
    print("Started WebSocket live updates broadcast thread")

    try:
        load_pbs_servers()
    except Exception as e:
        logging.warning(f"Failed to load PBS servers at startup: {e}")

    try:
        load_vmware_servers()
    except Exception as e:
        logging.warning(f"Failed to load VMware servers at startup: {e}")

    start_alert_thread()
    print("Started alert monitoring thread")

    start_scheduler_thread()
    print("Started task scheduler thread")

    start_password_expiry_thread()
    print("Started password expiry check thread")

    start_cross_cluster_lb_thread()
    print("Started cross-cluster load balancer thread")

    start_cross_cluster_replication_thread()
    print("Started cross-cluster replication scheduler thread")

    # Warm up pool cache
    def warmup_pool_cache():
        time.sleep(5)
        for cluster_id in g.cluster_managers:
            try:
                get_pool_membership_cache(cluster_id)
                print(f"  Pool cache warmed for cluster: {cluster_id}")
            except Exception as e:
                print(f"  Warning: Could not warm pool cache for {cluster_id}: {e}")

    threading.Thread(target=warmup_pool_cache, daemon=True).start()
    print("Started pool cache warmup thread")

    # Load server settings
    server_settings = load_server_settings()
    port = server_settings.get('port', 5000)
    bind_host = os.environ.get('PEGAPROX_HOST', '0.0.0.0')

    # Issue #71 (FireAmpersand): IPv6 support via PEGAPROX_HOST=::
    if ':' in bind_host and not _test_ipv6_available():
        print(f"WARNING: IPv6 bind address '{bind_host}' requested but IPv6 not available on this system")
        print("         Falling back to 0.0.0.0 (IPv4 only)")
        bind_host = '0.0.0.0'

    if ':' in bind_host:
        print(f"Binding to {bind_host} (dual-stack IPv4+IPv6)")

    ssl_enabled = server_settings.get('ssl_enabled', False)
    domain = server_settings.get('domain', '')
    app_name = server_settings.get('app_name', 'PegaProx')

    # Check for SSL certificates
    ssl_context = None
    if ssl_enabled and os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE):
        ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE)
        print("Custom SSL certificates found - starting with HTTPS")
    else:
        cert_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cert.pem')
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'key.pem')
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = (cert_file, key_file)
            print("SSL certificates found - starting with HTTPS")
        else:
            print("No SSL certificates found. Generating self-signed certificate...")
            try:
                from OpenSSL import crypto
                key = crypto.PKey()
                key.generate_key(crypto.TYPE_RSA, 2048)
                cert = crypto.X509()
                cert.get_subject().C = "DE"
                cert.get_subject().ST = "State"
                cert.get_subject().L = "City"
                cert.get_subject().O = app_name or "PegaProx"
                cert.get_subject().OU = app_name or "PegaProx"
                cert.get_subject().CN = domain or app_name or "PegaProx"
                cert.set_serial_number(1000)
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
                cert.set_issuer(cert.get_subject())
                cert.set_pubkey(key)
                cert.sign(key, 'sha256')
                with open(cert_file, "wb") as f:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                with open(key_file, "wb") as f:
                    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
                os.chmod(key_file, 0o600)
                ssl_context = (cert_file, key_file)
                print(f"Self-signed certificate generated: {cert_file}")
            except ImportError:
                print("WARNING: pyOpenSSL not installed. Run: pip install pyOpenSSL")
                print("Starting without HTTPS (noVNC may not work)")
            except Exception as e:
                print(f"WARNING: Could not generate SSL certificate: {e}")
                print("Starting without HTTPS (noVNC may not work)")

    # Start HTTP redirect server if SSL is enabled
    http_redirect_port = server_settings.get('http_redirect_port', 0)  # 0 = auto, -1 = disabled
    if http_redirect_port == 0:
        http_redirect_port = 80 if os.geteuid() == 0 else -1
    http_redirect_port = int(os.environ.get('PEGAPROX_HTTP_PORT', http_redirect_port))

    if ssl_context and http_redirect_port > 0:
        redirect_thread = threading.Thread(
            target=_start_http_redirect,
            args=(bind_host, http_redirect_port, port, domain),
            daemon=True
        )
        redirect_thread.start()
        print(f"Started additional HTTP -> HTTPS redirect on port {http_redirect_port}")

    # Determine workers
    cpu_count = multiprocessing.cpu_count()
    workers = int(os.environ.get('PEGAPROX_WORKERS', min(cpu_count * 2, 8)))

    print(f"System: {cpu_count} CPU cores detected")
    print(f"Memory optimization: Garbage collection tuned for {workers} workers")
    gc.set_threshold(700, 10, 10)

    # Start with Gevent if available
    use_gevent = os.environ.get('PEGAPROX_SERVER', 'auto').lower()

    if use_gevent == 'gevent' or (use_gevent == 'auto' and GEVENT_AVAILABLE):
        if GEVENT_AVAILABLE:
            _start_gevent_server(app, bind_host, port, ssl_context, domain, workers)
            return

    # Fallback to Flask development server
    print("Starting PegaProx with Flask development server")
    print("WARNING: Not recommended for production!")
    print("Install gevent for better performance: pip install gevent")

    vnc_ws_port = port + 1
    ssh_ws_port = port + 2

    # Start VNC/SSH WebSocket servers
    _start_console_servers(bind_host, port, ssl_context)

    if ssl_context:
        print(f"HTTPS on https://{bind_host}:{port}")
        app.run(host=bind_host, port=port, debug=False, ssl_context=ssl_context, threaded=True)
    else:
        print(f"HTTP on http://{bind_host}:{port}")
        app.run(host=bind_host, port=port, debug=False, threaded=True)


def _start_console_servers(bind_host, port, ssl_context):
    """Start VNC and SSH WebSocket servers."""
    # These are large functions extracted from the monolith
    # They will be imported from the original file on first run
    vnc_ws_port = port + 1
    ssh_ws_port = port + 2

    try:
        # Import the websocket server starters from the monolith
        # These are standalone async functions that run in their own threads
        from pegaprox.api.vms import start_vnc_websocket_server, start_ssh_websocket_server
        if ssl_context:
            start_vnc_websocket_server(vnc_ws_port, ssl_cert=ssl_context[0], ssl_key=ssl_context[1], host=bind_host)
            start_ssh_websocket_server(ssh_ws_port, ssl_cert=ssl_context[0], ssl_key=ssl_context[1], host=bind_host)
        else:
            start_vnc_websocket_server(vnc_ws_port, host=bind_host)
            start_ssh_websocket_server(ssh_ws_port, host=bind_host)
    except ImportError:
        print("WARNING: Console WebSocket servers not available")


def _test_ipv6_available():
    """Test if the system supports IPv6 sockets - Issue #71"""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('::', 0))
        s.close()
        return True
    except (OSError, socket.error):
        return False


def _start_http_redirect(bind_host, http_redirect_port, https_port, domain):
    """Start a simple HTTP server that redirects to HTTPS using raw sockets"""
    try:
        use_ipv6 = ':' in bind_host
        af = socket.AF_INET6 if use_ipv6 else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if use_ipv6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((bind_host, http_redirect_port))
        sock.listen(100)
        sock.settimeout(1.0)

        print(f"HTTP redirect server listening on port {http_redirect_port}")

        while True:
            try:
                client, addr = sock.accept()
                client.settimeout(5.0)
                try:
                    request = client.recv(4096).decode('utf-8', errors='ignore')
                    path = '/'
                    if request:
                        first_line = request.split('\r\n')[0]
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            path = parts[1].replace('\r', '').replace('\n', '')

                    host_header = ''
                    for line in request.split('\r\n'):
                        if line.lower().startswith('host:'):
                            host_value = line.split(':', 1)[1].strip()
                            if ':' in host_value:
                                host_header = host_value.rsplit(':', 1)[0]
                            else:
                                host_header = host_value
                            break

                    redirect_host = host_header or 'localhost'
                    if domain:
                        if ':' in domain and not domain.startswith('['):
                            redirect_host = domain.rsplit(':', 1)[0]
                        else:
                            redirect_host = domain

                    if https_port == 443:
                        redirect_url = f'https://{redirect_host}{path}'
                    else:
                        redirect_url = f'https://{redirect_host}:{https_port}{path}'

                    response = (
                        f"HTTP/1.1 301 Moved Permanently\r\n"
                        f"Location: {redirect_url}\r\n"
                        f"Content-Length: 0\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    client.sendall(response.encode())
                except Exception:
                    pass
                finally:
                    try:
                        client.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception as e:
                if 'Bad file descriptor' not in str(e):
                    logging.debug(f"HTTP redirect accept error: {e}")
                continue
    except PermissionError:
        print(f"WARNING: Cannot bind to port {http_redirect_port} (requires root). HTTP redirect not available.")
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f"WARNING: Port {http_redirect_port} already in use. HTTP redirect not available.")
        else:
            print(f"WARNING: HTTP redirect server failed: {e}")
    except Exception as e:
        print(f"WARNING: HTTP redirect server failed: {e}")


def _create_listener(bind_host, port_num):
    """Create a listener socket, IPv6 dual-stack if needed - Issue #71"""
    is_ipv6 = ':' in bind_host
    if is_ipv6:
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            listener.bind((bind_host, port_num))
            listener.listen(128)
            listener.setblocking(False)
            return listener
        except OSError as e:
            print(f"WARNING: IPv6 listener on port {port_num} failed ({e}), using IPv4")
            return ('0.0.0.0', port_num)
    else:
        return (bind_host, port_num)


def _start_gevent_server(app, bind_host, port, ssl_context, domain, workers):
    """Start production server with Gevent."""
    from gevent.pywsgi import WSGIServer

    print(f"Starting PegaProx with Gevent WSGIServer ({workers} greenlets)")
    print("Mode: Production (async I/O optimized)")

    # NS: Suppress noisy errors from bots/scanners/disconnects
    import logging as log_module
    log_module.getLogger('gevent').setLevel(log_module.CRITICAL)
    log_module.getLogger('gevent.pywsgi').setLevel(log_module.CRITICAL)
    log_module.getLogger('websockets').setLevel(log_module.CRITICAL)
    log_module.getLogger('websockets.server').setLevel(log_module.CRITICAL)
    log_module.getLogger('websockets.asyncio').setLevel(log_module.CRITICAL)

    # LW: Monkey-patch traceback to suppress SSL errors
    # gevent uses traceback.print_exception directly, bypassing logging
    import traceback as tb_module
    _original_print_exception = tb_module.print_exception
    _original_print_exc = tb_module.print_exc
    _original_format_exception = tb_module.format_exception

    def quiet_print_exception(exc, value=None, tb=None, limit=None, file=None, chain=True):
        exc_type = exc if isinstance(exc, type) else type(exc)
        if exc_type and 'ssl' in exc_type.__name__.lower():
            return
        if value and 'ssl' in str(value).lower():
            return
        _original_print_exception(exc, value, tb, limit, file, chain)

    def quiet_print_exc(limit=None, file=None, chain=True):
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_type and 'ssl' in exc_type.__name__.lower():
            return
        _original_print_exc(limit, file, chain)

    def quiet_format_exception(exc, value=None, tb=None, limit=None, chain=True):
        exc_type = exc if isinstance(exc, type) else type(exc)
        if exc_type and 'ssl' in exc_type.__name__.lower():
            return []
        return _original_format_exception(exc, value, tb, limit, chain)

    tb_module.print_exception = quiet_print_exception
    tb_module.print_exc = quiet_print_exc
    tb_module.format_exception = quiet_format_exception

    # NS: Also filter stderr directly as last resort
    import io
    class SSLFilteredStderr:
        def __init__(self, original):
            self._original = original
            self._buffer = []
            self._in_ssl_traceback = False

        def write(self, text):
            if 'Traceback (most recent call last):' in text:
                self._in_ssl_traceback = False
                self._buffer = [text]
                return len(text)
            if self._buffer:
                self._buffer.append(text)
                full_text = ''.join(self._buffer)
                if 'SSLEOFError' in full_text or 'ssl.SSL' in full_text:
                    self._in_ssl_traceback = True
                if text.strip() and not text.startswith(' ') and not text.startswith('Traceback'):
                    if self._in_ssl_traceback:
                        self._buffer = []
                        self._in_ssl_traceback = False
                        return len(text)
                    else:
                        for line in self._buffer:
                            self._original.write(line)
                        self._buffer = []
                return len(text)
            return self._original.write(text)

        def flush(self):
            if self._buffer and not self._in_ssl_traceback:
                for line in self._buffer:
                    self._original.write(line)
            self._buffer = []
            self._original.flush()

        def __getattr__(self, name):
            return getattr(self._original, name)

    sys.stderr = SSLFilteredStderr(sys.stderr)

    os.environ['GEVENT_DEBUG'] = 'off'

    # WebSocket handler
    use_websocket_handler = False
    try:
        from geventwebsocket.handler import WebSocketHandler
        use_websocket_handler = True
        print("WebSocket support: geventwebsocket enabled")
    except ImportError:
        use_websocket_handler = False
        print("WebSocket support: geventwebsocket NOT installed")
        print("  Install with: pip install gevent-websocket")

    # NS: Custom handler to suppress SSL error tracebacks completely
    # These happen when users close browser tabs - totally normal
    if use_websocket_handler:
        class QuietWebSocketHandler(WebSocketHandler):
            def handle_one_response(self):
                try:
                    return super().handle_one_response()
                except Exception as e:
                    if 'ssl' in type(e).__name__.lower() or 'ssl' in str(e).lower():
                        return
                    raise

            def log_error(self, msg, *args):
                if 'ssl' in str(msg).lower() or 'eof' in str(msg).lower():
                    return
                super().log_error(msg, *args)
    else:
        QuietWebSocketHandler = None

    # Custom error handler to suppress SSL errors (from bots/scanners/disconnects)
    class QuietWSGIServer(WSGIServer):
        def wrap_socket_and_handle(self, client_socket, address):
            """Override to catch SSL errors during handshake"""
            try:
                return super().wrap_socket_and_handle(client_socket, address)
            except Exception as e:
                if 'ssl' in str(type(e).__name__).lower() or 'ssl' in str(e).lower():
                    pass
                else:
                    raise

        def handle_error(self, *args):
            """Suppress SSL errors - they're normal with self-signed certs"""
            exc_info = sys.exc_info()
            exc_type = exc_info[0]
            if exc_type is not None:
                if 'ssl' in exc_type.__name__.lower():
                    return
            pass

        def log_error(self, msg, *args):
            """Suppress SSL error logging"""
            msg_lower = str(msg).lower()
            if 'ssl' in msg_lower or 'eof' in msg_lower or 'broken pipe' in msg_lower:
                return
            print(f"[Server Error] {msg % args if args else msg}")

    # DualProtocolWSGIServer - HTTP and HTTPS on same port
    # If someone visits http://server:5000, they get redirected to https://server:5000
    # MK: Claude helped with the TLS detection logic - checking for 0x16/0x80 bytes
    class DualProtocolWSGIServer(QuietWSGIServer):
        """WSGI Server that detects HTTP vs HTTPS and redirects HTTP to HTTPS"""

        def __init__(self, *args, redirect_domain=None, **kwargs):
            self._redirect_domain = redirect_domain
            super().__init__(*args, **kwargs)

        def wrap_socket_and_handle(self, client_socket, address):
            """Peek at first bytes to detect protocol"""
            if not self.ssl_args:
                return super().wrap_socket_and_handle(client_socket, address)
            try:
                first_byte = client_socket.recv(1, socket.MSG_PEEK)
                if not first_byte:
                    client_socket.close()
                    return
                if first_byte[0] == 0x16 or first_byte[0] == 0x80:
                    return super().wrap_socket_and_handle(client_socket, address)
                else:
                    self._handle_http_redirect(client_socket, address)
                    return
            except Exception as e:
                if 'ssl' in str(type(e).__name__).lower():
                    return
                try:
                    return super().wrap_socket_and_handle(client_socket, address)
                except Exception:
                    pass

        def _handle_http_redirect(self, client_socket, address):
            """Send HTTP 301 redirect to HTTPS version"""
            try:
                client_socket.settimeout(5.0)
                request_data = b''
                while b'\r\n\r\n' not in request_data and len(request_data) < 8192:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    request_data += chunk

                request = request_data.decode('utf-8', errors='ignore')
                path = '/'
                if request:
                    first_line = request.split('\r\n')[0]
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        path = parts[1].replace('\r', '').replace('\n', '')

                host = self._redirect_domain or 'localhost'
                for line in request.split('\r\n'):
                    if line.lower().startswith('host:'):
                        host_value = line.split(':', 1)[1].strip()
                        if host_value.startswith('['):
                            if ']:' in host_value:
                                host = host_value.rsplit(':', 1)[0]
                            else:
                                host = host_value
                        elif ':' in host_value:
                            host = host_value.rsplit(':', 1)[0]
                        else:
                            host = host_value
                        break

                if self._redirect_domain:
                    d = self._redirect_domain
                    if ':' in d and not d.startswith('['):
                        host = d.rsplit(':', 1)[0]
                    else:
                        host = d

                server_port = self.server_port
                if server_port == 443:
                    redirect_url = f'https://{host}{path}'
                else:
                    redirect_url = f'https://{host}:{server_port}{path}'

                response = (
                    f"HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: {redirect_url}\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                client_socket.sendall(response.encode())
            except Exception:
                pass
            finally:
                try:
                    client_socket.close()
                except Exception:
                    pass

    # Server args - add WebSocket handler if available
    server_kwargs = {'log': None}
    if use_websocket_handler and QuietWebSocketHandler:
        server_kwargs['handler_class'] = QuietWebSocketHandler

    is_ipv6_bind = ':' in bind_host

    if ssl_context:
        print(f"HTTPS on https://{bind_host}:{port}")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(ssl_context[0], ssl_context[1])
        http_server = DualProtocolWSGIServer(
            _create_listener(bind_host, port), app,
            ssl_context=ssl_ctx,
            redirect_domain=domain,
            **server_kwargs
        )
    else:
        print(f"HTTP on http://{bind_host}:{port}")
        print("WARNING: Running without HTTPS - noVNC console may not work!")
        http_server = QuietWSGIServer(_create_listener(bind_host, port), app, **server_kwargs)

    # Start VNC/SSH WebSocket servers
    _start_console_servers(bind_host, port, ssl_context)

    # Handle graceful shutdown
    def signal_handler(signum, frame):
        print("\nShutting down gracefully...")
        http_server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("SSL/WebSocket errors (bots, scanners, disconnects) are suppressed")
    http_server.serve_forever()
