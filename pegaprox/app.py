# -*- coding: utf-8 -*-
"""
PegaProx Flask App Factory - Layer 8
Creates and configures the Flask application.
"""

import io
import json
import os
import re
import sys
import time
import errno
import stat
import logging
import threading
import signal
import gc
import multiprocessing
import ssl
import socket
from greenlet import GreenletExit

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sock import Sock
from flask_compress import Compress
from pathlib import Path
from werkzeug.datastructures import EnvironHeaders

from pegaprox.constants import (
    PEGAPROX_VERSION, PEGAPROX_BUILD,
    SESSION_TIMEOUT, SSL_CERT_FILE, SSL_KEY_FILE, SSL_DIR,
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
    _upload_max = int(os.environ.get('PEGAPROX_MAX_UPLOAD_SIZE', 100 * 1024 * 1024 * 1024))  # MK: 100 GB for uploads (#116)
    app.config['MAX_CONTENT_LENGTH'] = _upload_max  # set high, we check per-route below

    # Request validation & rate limiting
    # LW: Mar 2026 - ACME HTTP-01 challenge route, must be unauthenticated (#96)
    @app.route('/.well-known/acme-challenge/<token>')
    def acme_challenge(token):
        from pegaprox.core.acme import get_challenge_response
        response = get_challenge_response(token)
        if response:
            return response, 200, {'Content-Type': 'text/plain'}
        return '', 404

    @app.before_request
    def validate_request():
        if request.path.startswith('/static/') or request.path.startswith('/images/'):
            return None
        if request.path.startswith('/ws'):
            return None
        # MK: Mar 2026 - ACME challenges must bypass all security checks (#96)
        if request.path.startswith('/.well-known/'):
            return None

        # NS: Feb 2026 - per-route size limits: uploads get the big limit, everything else 10MB
        # MK: Mar 2026 - removed global config mutation, was causing 413s on subsequent uploads (#119)
        is_upload = request.path.endswith('/upload')
        max_size = _upload_max if is_upload else _default_max
        if request.content_length and request.content_length > max_size:
            return jsonify({'error': f'Request too large. Max {max_size // (1024*1024)} MB'}), 413
        # H-6 (security audit): a chunked Transfer-Encoding request carries NO
        # Content-Length, so the check above is skipped and an unauth client could
        # stream an unbounded body → OOM DoS. Pin werkzeug's per-request cap so the
        # limit is enforced when the body is actually read (counts real bytes,
        # works for chunked too). Per-request, not a global config mutation — so
        # uploads keep their big ceiling without the #119 cross-request race.
        try:
            request.max_content_length = max_size
        except Exception:
            pass

        if request.path.startswith('/api/'):
            skip_paths = ['/api/auth/login', '/api/auth/check', '/api/events', '/api/health', '/api/sse',
                          '/api/vmware/migrations']
            # MK Sep 2026 (#625) - a group member's signed call is not a client: every
            # write a standby forwards comes from its one address, next to its sync, and
            # the forwarded request counts against the client's own address inside
            peer_call = False
            if request.path.startswith('/api/ha/peer/'):
                from pegaprox.api.ha import signed_member_call
                peer_call = signed_member_call()
            if not peer_call and not any(request.path.startswith(p) for p in skip_paths):
                # NS: Mar 2026 - use centralized get_client_ip, respects trusted_proxies
                from pegaprox.utils.audit import get_client_ip
                client_ip = get_client_ip()

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

        # NS: Mar 2026 — CSRF check for multipart uploads.
        # MK May 2026 (audit fix H-1) — also enforced for application/json
        # POST/PUT/PATCH/DELETE. Earlier the assumption was "JSON triggers
        # CORS preflight which blocks cross-origin", which is true for the
        # browser path but doesn't help against subdomain takeover, mis-
        # configured trusted-proxy reflecting Origin, or non-browser tools
        # that already have a session cookie. So now: every state-changing
        # /api/* request must come with X-Requested-With or a matching Origin.
        # Exempt: unauth flows (login, OIDC redirects) where we have no
        # session yet to protect.
        _CSRF_EXEMPT = (
            '/api/auth/login',
            '/api/auth/setup',  # MK May 2026 — first-run wizard, no session yet
            '/api/auth/oidc/authorize',
            '/api/auth/oidc/callback',
            '/api/auth/oidc/config',
            '/api/auth/check',
            '/api/auth/validate',
            '/api/auth/logout',  # logout is idempotent + harmless
            '/api/health',
            '/api/webauthn/auth/begin',
            '/api/webauthn/auth/finish',
            # MK Sep 2026 - the automated installer is not a browser: it carries no
            # session to protect and cannot be made to send Origin or X-Requested-With.
            # Both of these are gated by the installation token instead.
            '/api/auto-install/answer',
            '/api/auto-install/progress',
        )
        if (request.method in ('POST', 'PUT', 'PATCH', 'DELETE')
                and request.path.startswith('/api/')
                and request.path not in _CSRF_EXEMPT):
            # NS Jul 2026 (CodeAnt CSRF) — the CSRF check must run for EVERY state-changing
            # non-exempt /api/* request, not only JSON/form bodies: a cross-site form with
            # enctype=text/plain is a browser "simple request" that previously skipped this gate.
            if True:
                has_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                origin = request.headers.get('Origin', '')
                referer = request.headers.get('Referer', '')
                allowed_origins = get_allowed_origins() or []
                # NS: only trust the forwarded host from a trusted proxy — otherwise a client
                # sets X-Forwarded-Host to its own domain and its foreign Origin matches.
                # (Same discipline as X-Forwarded-Proto in add_security_headers below.)
                from pegaprox.utils.audit import _is_trusted_proxy
                fwd_host = (request.headers.get('X-Forwarded-Host', '')
                            if _is_trusted_proxy(request.remote_addr) else '')

                # NS May 2026 (#382 follow-up) — safer Origin matcher.
                # The previous version used `value.startswith(f"{scheme}://{host}")`
                # which (a) had a suffix-confusion bug — `https://pegaprox.com`
                # would match an Origin of `https://pegaprox.com.attacker.com`
                # because that string really does start with the substring —
                # and (b) was strict about scheme, which broke users behind
                # Apache/nginx reverse proxies that don't forward
                # X-Forwarded-Proto (cklabautermann's report).
                # New approach: parse the URL, compare *hostname* (and port
                # if both sides specify one). Scheme is irrelevant for CSRF;
                # the browser controls Origin and won't lie about hostname.
                # HTTPS enforcement happens elsewhere (HSTS, secure cookie flag).
                from urllib.parse import urlparse

                def _collapse_folded_host(hp):
                    # NS Jul 2026 (#626) — a duplicated `Host` header (e.g. a reverse
                    # proxy injecting its own Host on top of one the client already
                    # sent) is folded by the WSGI layer into a comma-joined value such
                    # as "example.com, example.com". Collapse it ONLY when every part
                    # is identical; a value carrying genuinely different hosts is
                    # ambiguous/hostile and is left intact so it fails the match below
                    # (fail-closed — we never pick one host out of a conflicting set).
                    if ',' not in hp:
                        return hp
                    parts = [p.strip() for p in hp.split(',') if p.strip()]
                    # Host names are case-insensitive, so "Example.com, example.com"
                    # is still one host — collapse it. Genuinely different hosts
                    # (even ignoring case) are left intact and fail the match.
                    if parts and all(p.lower() == parts[0].lower() for p in parts):
                        return parts[0]
                    return hp

                def _host_port(hp):
                    # split request.host or fwd_host into (host, port|None)
                    if not hp: return ('', None)
                    hp = _collapse_folded_host(hp)
                    if ':' in hp:
                        h, _, p = hp.rpartition(':')
                        try: return (h.lower(), int(p))
                        except ValueError: return (hp.lower(), None)
                    return (hp.lower(), None)

                req_host, req_port = _host_port(request.host)
                fwd_h, fwd_p = _host_port(fwd_host)

                def _origin_ok(value):
                    if not value: return False
                    if value in allowed_origins:
                        return True
                    # NS May 2026 (pentest finding) — Python's urlparse silently
                    # normalises tabs/whitespace inside the scheme: 'ht\ttp://x'
                    # parses as scheme='http'. Browsers never produce that, but
                    # an attacker with raw HTTP control could craft it. Lock the
                    # scheme prefix down with a strict, byte-exact check before
                    # parsing — only the two browser-realistic prefixes pass.
                    if not (value.startswith('http://') or value.startswith('https://')):
                        return False
                    try:
                        u = urlparse(value)
                        # MK May 2026: u.port can ValueError for malformed authority
                        # like "localhost:5000.attacker.com" — guard explicitly.
                        try:
                            cand_port = u.port
                        except (ValueError, TypeError):
                            return False
                    except Exception:
                        return False
                    # Defensive: reject userinfo. RFC 6454 origins have no userinfo;
                    # `http://evil.com:****@localhost` parses with hostname=localhost,
                    # which would otherwise slip through.
                    if u.username or u.password:
                        return False
                    if u.scheme not in ('http', 'https'):  # belt + braces
                        return False
                    if not u.hostname:
                        return False
                    cand_host = u.hostname.lower()
                    # A portless Origin implies its scheme's default port
                    # (https -> 443, http -> ****). Comparing that *effective* port
                    # (NS Jul 2026, #626 hardening) keeps an https Origin from ever
                    # matching a :**** target, while the common reverse-proxy cases
                    # (portless Origin vs the site's default-port Host, or vs a
                    # proxy-dropped unknown port) still pass. https://host:9999 is
                    # never accepted against an unknown-port target.
                    eff_cand = cand_port if cand_port is not None else (443 if u.scheme == 'https' else ****)
                    # accept against request host or proxy-forwarded host
                    targets = [(req_host, req_port)]
                    if fwd_h:
                        targets.append((fwd_h, fwd_p))
                    for t_host, t_port in targets:
                        if cand_host != t_host:
                            continue
                        if t_port is None:
                            # target port unknown (proxy dropped it) — accept only a
                            # standard :****/:443 origin, never e.g. https://host:9999.
                            if eff_cand in (****, 443):
                                return True
                        elif eff_cand == t_port:
                            return True
                        # any other combination is a real port mismatch → reject
                    return False

                # accept either a same-origin Origin/Referer OR XHR + same-origin
                # (XHR alone is not enough — fetch() lets attacker set X-R-W on
                # same-origin, but cross-origin requests can also set it freely
                # in non-browser contexts).
                # MK May 2026: Referer parses as a full URL — pass it directly to
                # _origin_ok which now uses urlparse, no manual splitting needed.
                # Origin is authoritative when the browser sends it: a matching Referer must not
                # rescue a foreign Origin (the `origin and not _origin_ok(origin)` guard below sits
                # inside the not-ok_origin branch, so a same-host Referer skipped it entirely).
                if origin:
                    ok_origin = _origin_ok(origin)
                else:
                    ok_origin = _origin_ok(referer)
                if not ok_origin:
                    # If neither Origin nor Referer matches, only allow when XHR
                    # marker is set AND there's no foreign Origin/Referer.
                    if not has_xhr:
                        return jsonify({'error': 'CSRF validation failed'}), 403
                    if origin and not _origin_ok(origin):
                        return jsonify({'error': 'CSRF validation failed'}), 403
                    if referer and not _origin_ok(referer):
                        return jsonify({'error': 'CSRF validation failed'}), 403

        return None

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # NS May 2026 (#381) — relaxed from DENY to SAMEORIGIN so plugins
        # can ship a frontend UI that the dashboard embeds in an iframe tab.
        # Cross-origin clickjacking remains prevented; same-origin embedding
        # is the documented plugin-frontend contract.
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        # MK: Mar 2026 - tightened CSP, removed dead tailwindcss CDN ref (#118)
        # NS May 2026 (#381) — frame-ancestors 'self' instead of 'none' to
        # match the X-Frame-Options switch above. This is the modern equivalent.
        csp = (
            "default-src 'self'; "
            # NS Jul 2026 (CodeAnt config) — 'unsafe-eval' dropped: Babel is pre-compiled at build
            # time (web/Dev/build.sh) and never runs in the browser, so nothing needs eval().
            "script-src 'self' 'unsafe-inline' "
                "https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' "
                "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' wss: ws: https://cdn.jsdelivr.net; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers['Content-Security-Policy'] = csp

        # LW: Mar 2026 - only trust X-Forwarded-Proto from trusted proxies
        from pegaprox.utils.audit import _is_trusted_proxy
        is_https = request.is_secure or (_is_trusted_proxy(request.remote_addr) and request.headers.get('X-Forwarded-Proto') == 'https')
        if is_https:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # NS: kein Cache fuer API/auth-stuff, sonst leakt session-state via shared
        # caches (browser-cache nach logout, reverse-proxy mit zu generouser
        # cache config, browser-back-button mit cred response). semgrep findung
        # vom 2026-05-06. /static/* darf weiter gecacht werden, das sind die
        # JS-libs.
        path = request.path or ''
        if path.startswith('/api/') or path in ('/', '/portal', '/oidc/callback'):
            # don't override if a route explicitly set its own Cache-Control
            if 'Cache-Control' not in response.headers:
                response.headers['Cache-Control'] = 'no-store, private'
                response.headers['Pragma'] = 'no-cache'  # http/1.0 fallback, harmless

        return response

    # Register all API blueprints
    register_blueprints(app)

    # MK Sep 2026 (#625) - a standby takes its configuration from the active instance
    # and would lose a local change at the next sync, so it refuses writes. With the
    # live view on it also holds connections to the clusters, and a write there is an
    # action on them (start, migrate, delete) that only the active takes. Registered
    # here and not in validate_request: before_request hooks run in registration
    # order, and the IP allow list is hooked in by the settings blueprint above, so
    # this runs after the CSRF, rate-limit and IP checks.
    # Open on a standby: the pairing/promotion routes and signing in and out. A TOTP
    # code travels inside /api/auth/login. Enrolment (/api/auth/2fa/*), setup, password
    # changes, tokens and preferences are writes like any other: refused here, and
    # forwarded to the active while forwarding is on.
    _STANDBY_WRITABLE = (
        '/api/auth/login',
        '/api/auth/logout',
        '/api/auth/oidc/callback',
        '/api/webauthn/auth/begin',
        '/api/webauthn/auth/finish',
    )
    # Writes that only ever change this instance, so no sync can undo them and nothing
    # would be lost. Matched on the route that serves the request, not on the path
    # text, so a parameter or an encoded character cannot stretch an entry.
    # Not POST /api/settings/server: one body mixes local keys with synced ones.
    _STANDBY_LOCAL_WRITES = frozenset((
        # the caller's own session; sessions are per instance and never synced
        ('DELETE', '/api/user/sessions/<token>'),
        # the live stream: its short-lived token and which clusters it carries, both in
        # memory here. Not /api/ws/token - every caller of that one opens a console,
        # which _STANDBY_CONSOLES below decides.
        ('POST', '/api/sse/token'),
        ('POST', '/api/sse/subscribe'),
        # a read that takes its filter in the body; the GET beside it is open anyway
        ('POST', '/api/snapshots/overview'),
        # the ESXi VM detail watch: which VMs the live stream pushes details for, a dict
        # in this process like the SSE subscription (vmware.vm.view, the per-server
        # check still applies). The push only reads the VM, its guest info and its
        # performance from the ESXi host.
        ('POST', '/api/vmware/<vmware_id>/vms/<vm_id>/watch'),
        ('DELETE', '/api/vmware/<vmware_id>/vms/<vm_id>/watch'),
        # restarts this process and changes nothing
        ('POST', '/api/settings/server/restart'),
        # Not the ACME request and DNS-complete routes and not the hardware-monitoring
        # consent, although what they mean to change is local: each saves back the whole
        # settings dict it loaded, so a sync that lands in between (the ACME call waits
        # 30 s for DNS) is overwritten with the older copy until the active changes
        # something. Set those before pairing or after promotion.
        # login lockouts are counters in this process
        ('DELETE', '/api/security/locked-ips/<ip_address>'),
        ('DELETE', '/api/security/locked-users/<username>'),
        ('DELETE', '/api/security/locked-ips'),
        ('DELETE', '/api/security/locked-users'),
    ))
    # Consoles: a standby that serves users opens them itself, for the browser sessions
    # it serves, the way an active instance does. Any other standby opens none and hands
    # none on, the UI offers the active instance instead (ha.CONSOLE_WRITES).
    from pegaprox.core.ha import CONSOLE_WRITES as _STANDBY_CONSOLES
    # v3: a write refused here goes to the active instead, when a signed-in browser sent
    # it (api/ha.py forward_to_active). These stay refused.
    _STANDBY_NOT_FORWARDED = frozenset((
        # This instance's own settings: run on the active they would set the active's
        # port, domain, certificate and so on to what the form here shows. The server
        # form sends its local keys every time, whatever else changed.
        ('POST', '/api/settings/server'),
        ('POST', '/api/settings/acme/request'),
        ('POST', '/api/settings/acme/dns/complete'),
        ('POST', '/api/hardware-monitoring/consent'),
        ('POST', '/api/hardware-monitoring/redfish-consent'),
        ('POST', '/api/config/restore'),
        ('POST', '/api/security/cors'),
        # MK Oct 2026 - the broadcast banners, stored with the settings: a standby shows
        # them and leaves them to the settings page of the active
        ('POST', '/api/settings/banners'),
        ('PUT', '/api/settings/banners/<banner_id>'),
        ('DELETE', '/api/settings/banners/<banner_id>'),
        # the code and the loaded plugins of a process: an update or a plugin switched
        # on would happen to the active and not here
        ('POST', '/api/pegaprox/update'),
        ('POST', '/api/pegaprox/update/rollback'),
        ('POST', '/api/plugins/<plugin_id>/reload'),
        ('POST', '/api/plugins/<plugin_id>/enable'),
        ('POST', '/api/plugins/<plugin_id>/disable'),
        ('POST', '/api/plugins/rescan'),
        ('DELETE', '/api/plugins/<plugin_id>'),
        ('POST', '/api/clusters/<cluster_id>/pools/refresh-cache'),
        # a security key is bound to the host the browser sees, and the active would
        # answer for its own
        ('POST', '/api/webauthn/register/begin'),
        ('POST', '/api/webauthn/register/finish'),
        # rows of tables every instance keeps for itself, named by an id from this one's
        # copy: on the active the same id is another row, or none. Not the drift, alert
        # and inbox acks: a forwarding standby reads those lists from the active
        # (ha.FORWARDED_READS), so their ids are the active's
        ('DELETE', '/api/auto-install/runs/<run_id>'),
        ('POST', '/api/insights/force-snapshot'),
    ))
    # The plugin proxy, and the plugin routes behind it that open a console. A plugin
    # handler serves every method from one function and most never look at which one
    # they got, so a GET reaches their write paths too: on a standby nothing of a plugin
    # runs but its console where consoles open. Its GETs are read on the active while
    # this standby forwards, its writes go there like any other.
    from pegaprox.core.ha import (FORWARDED_READS as _ha_forwarded_reads,
                                  FORWARD_ENVIRON as _FORWARD_ENVIRON,
                                  PLUGIN_PROXY_RULE as _PLUGIN_PROXY_RULE,
                                  PLUGIN_CONSOLE_PATHS as _PLUGIN_CONSOLE_PATHS)

    @app.before_request
    def refuse_writes_on_standby():
        rule = request.url_rule.rule if request.url_rule is not None else None
        if request.method == 'GET' and rule in _ha_forwarded_reads:
            # the progress of a job the active runs, or a view only its tables hold: from
            # there while this standby hands its writes on, else our own (empty) copy.
            # The task lists only for an XCP-ng pool (ha.XCPNG_TASK_READS)
            from pegaprox.core import ha
            if ha.is_standby() and ha.forwards_read(rule, request.view_args):
                from pegaprox.api.ha import forward_to_active
                return forward_to_active(read=True)
            return None
        plugin_call = rule == _PLUGIN_PROXY_RULE
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE') and not plugin_call:
            return None
        path = request.path
        if not path.startswith('/api/') or path.startswith('/api/ha/') or path in _STANDBY_WRITABLE:
            return None
        if (request.method, rule) in _STANDBY_LOCAL_WRITES:
            return None
        from pegaprox.core import ha
        view_args = request.view_args or {}
        if not ha.is_standby():
            # MK Oct 2026 (#625) - the leader hands its lead on: writes wait until the
            # member it goes to caught up (design 7.1)
            active = ha.is_active()
            pausing = active and ha.handing_over()
            if active and not pausing:
                return None
            # MK Oct 2026 (#625) - automatic failover: this instance leads and holds no
            # lease right now (it ran out, or the takeover wait is on). A change taken now
            # might be one the next leader never sees. The consoles stay: they are the
            # user's, on the instance the browser is on.
            if (request.method, rule) in _STANDBY_CONSOLES or (
                    plugin_call and view_args.get('subpath') in _PLUGIN_CONSOLE_PATHS):
                return None
            if pausing:
                from pegaprox.api.ha import transfer_refusal
                return transfer_refusal()
            # never None: is_active() said no, and a second look at the state may find a
            # standby by now, which would wave the write through
            from pegaprox.api.ha import write_gate_refusal
            return write_gate_refusal()
        if plugin_call and view_args.get('subpath') in _PLUGIN_CONSOLE_PATHS:
            # never forwarded: the browser connects to the instance that opened it. Where
            # consoles open, only for a plugin the leader runs as well - one switched off
            # there stays loaded in this process until it restarts, so the synced
            # plugin_state decides, not what is loaded here
            from pegaprox.api.ha import by_api_token, PLUGIN_CONSOLE_ERROR
            if ha.consoles_here() and not by_api_token():
                from pegaprox.api.plugins import plugin_runs_here
                if plugin_runs_here(view_args.get('plugin_id')):
                    return None
                return jsonify({'error': PLUGIN_CONSOLE_ERROR, 'code': 'HA_STANDBY'}), 409
            forwardable = False
        elif (request.method, rule) in _STANDBY_CONSOLES:
            from pegaprox.api.ha import by_api_token
            if ha.consoles_here() and not by_api_token():
                return None
            forwardable = False
        elif plugin_call and request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            # a GET of a plugin is read on the active, and nowhere when that does not
            # answer: run here it could change this copy. HEAD and OPTIONS go nowhere
            from pegaprox.api.ha import forward_to_active
            read = forward_to_active(read=True)
            if read is not None:
                return read
            forwardable = False
        else:
            # a path no route serves goes nowhere: forwarded, it would only cost the active
            forwardable = rule is not None and (request.method, rule) not in _STANDBY_NOT_FORWARDED
        if forwardable:
            from pegaprox.api.ha import forward_to_active
            forwarded = forward_to_active()
            if forwarded is not None:
                return forwarded
        return jsonify({
            'error': 'This is a standby instance. Make changes and act on the active '
                     'instance; its configuration arrives here with the next sync.',
            'code': 'HA_STANDBY',
        }), 409

    # A read can change shared configuration as well: a plugin serves every method from
    # one function, and the leader runs the reads its members hand over. Around those
    # the leader takes the change count of the shared tables and files (ha.read_mark),
    # and one that moved it tells the members like a write (below). Counted, not guessed
    # from the route: most of them change nothing.
    _READ_MARK = 'pegaprox.ha_read_mark'

    @app.before_request
    def count_around_a_read():
        if request.method != 'GET':
            return None
        rule = request.url_rule.rule if request.url_rule is not None else None
        if rule != _PLUGIN_PROXY_RULE and request.environ.get(_FORWARD_ENVIRON) is None:
            return None
        from pegaprox.core import ha
        mark = ha.read_mark()
        if mark is not None:
            request.environ[_READ_MARK] = mark
        return None

    # The active tells its members after a write, so the change shows there in seconds
    # and not at their next poll (ha.nudge_members, one call for a burst). A forwarded
    # write runs through here on the active as well. Not for the HA routes, not for the
    # writes above that only ever change this instance (signing in, the live stream)
    # and not for the consoles: the members would only find nothing new, and a console
    # over vnc-poll sends a POST for every screen update and key press while it is open.
    @app.after_request
    def tell_the_members_about_a_write(response):
        try:
            if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and 200 <= response.status_code < 300:
                path = request.path
                rule = request.url_rule.rule if request.url_rule is not None else None
                if (path.startswith('/api/') and not path.startswith('/api/ha/')
                        and path not in _STANDBY_WRITABLE
                        and (request.method, rule) not in _STANDBY_LOCAL_WRITES
                        and (request.method, rule) not in _STANDBY_CONSOLES
                        and not (rule == _PLUGIN_PROXY_RULE and (request.view_args or {}).get(
                            'subpath') in _PLUGIN_CONSOLE_PATHS)):
                    _note_and_nudge()
            elif _READ_MARK in request.environ:
                # the count says something changed while it ran: the members pull either
                # way, but only a read that went through for a signed-in user is the
                # journal's "who wrote it" - another connection may have made the change
                from pegaprox.core import ha
                if ha.read_mark() != request.environ[_READ_MARK]:
                    # a forwarded read runs for the signed-in user its member vouched for
                    signed_in = (bool((getattr(request, 'session', None) or {}).get('user'))
                                 or request.environ.get(ha.FORWARD_ENVIRON) is not None)
                    _note_and_nudge(journal=signed_in and 200 <= response.status_code < 300)
        except Exception as e:
            logging.debug(f"[HA] no note to the members after {request.path}: {e}")
        return response

    def _note_and_nudge(journal=True):
        from pegaprox.core import ha
        # who wrote what, for the copy a member keeps should a sync not carry it over
        # (ha.note_write)
        if journal:
            mark = request.environ.get(ha.FORWARD_ENVIRON)
            ha.note_write((getattr(request, 'session', None) or {}).get('user', ''),
                          request.method, request.path,
                          mark.get('via') if isinstance(mark, dict) else '')
        ha.nudge_members()

    # MK Oct 2026 (#625) - a write the exit refused in an automatic group (ha.guard: the
    # lease ran out, or no majority confirmed it) reaches most routes as a failed cluster
    # call, and they answered 400 or 500 with the guard's own words. The caller hears what
    # the write gate says instead: 503 HA_NO_LEASE, try again. A 2xx for what did go out
    # and a 503 of the route's own stay as they are.
    @app.after_request
    def say_no_lease_after_a_refused_write(response):
        if 400 <= response.status_code < 600 and response.status_code != 503:
            from pegaprox.core import ha
            if request.environ.get(ha.GUARD_REFUSED_ENVIRON):
                from pegaprox.api.ha import guard_refusal
                resp, status = guard_refusal()
                resp.status_code = status
                return resp
        return response

    # and the same for a refusal that no route caught on its way up
    from pegaprox.core.ha import NoLease

    @app.errorhandler(NoLease)
    def refused_at_the_exit(e):
        from pegaprox.api.ha import guard_refusal
        return guard_refusal()

    # the lease calls of automatic failover, answered before Flask where Flask would
    # answer them with 200 anyway (_LeaseFastPath). It takes the hooks as they are now,
    # before any plugin is loaded: one that hooks into requests turns it off
    app.wsgi_app = _LeaseFastPath(app, app.wsgi_app, _default_max)

    # Load enabled plugins
    from pegaprox.api.plugins import load_enabled_plugins
    load_enabled_plugins(app)

    return app


# --- the lease calls of automatic failover, before Flask -------------------------------------
#
# MK Oct 2026 (#625) - a leader in automatic mode renews its lease before every write, so
# a member answers renewals many times a second. Through Flask one cost a member about
# 1.0 ms of CPU (2 ms with TLS and pywsgi), more than three times the answer itself: a
# request context and the URL map, the CSRF, rate-limit and IP hooks, the signature
# checked twice (once before the body for the rate limit), the after-request headers.
# Here it is 0.37 ms (1.05 ms with TLS and pywsgi).
# _LeaseFastPath answers POST /api/ha/peer/renew and /api/ha/peer/vote in the WSGI layer
# instead, and only a call the Flask path would answer with 200 as well: a member we hold
# a key of signed it, the IP lists let its address through (settings.ip_lists_pass, the
# function check_ip_whitelist goes by), its body is within both caps, its headers are what
# the CSRF and content-type checks take, and nothing asks a hook to act (compression, a
# CORS setup, a hook nobody here looked at). Anything else goes down the Flask path
# untouched and is refused there as before. The one thing done before that is known is
# the signature check; it spends the nonce, so its verdict goes along (api/ha.py
# request_peer) and a call is judged once whichever way it takes.

_LEASE_ROUTES = {'/api/ha/peer/renew': 'renew', '/api/ha/peer/vote': 'vote'}
_LENGTH_RE = re.compile(r'[0-9]{1,9}')
# the hooks the fast path stands in for, by name: what each does for these two routes is
# done above or cannot apply (refuse_writes_on_standby lets /api/ha/ through,
# count_around_a_read and tell_the_members_about_a_write look at other methods and paths,
# say_no_lease_after_a_refused_write at a refusal of an exit, and these send through none)
_STOOD_IN_FOR = {
    'before': ('validate_request', 'check_ip_whitelist', 'refuse_writes_on_standby',
               'count_around_a_read'),
    'after': ('after_request', 'add_security_headers', 'tell_the_members_about_a_write',
              'say_no_lease_after_a_refused_write', '_say_we_hold_the_key'),
}


def _request_hooks(app):
    """The functions Flask runs around a request of the 'ha' blueprint, in order."""
    out = []
    for table in (app.before_request_funcs, app.after_request_funcs, app.teardown_request_funcs,
                  app.url_value_preprocessors):
        for key in (None, 'ha'):
            out.append(tuple(table.get(key, ())))
    return tuple(out)


def _hooks_known(app):
    def names(table):
        return sorted(getattr(f, '__name__', '') for key in (None, 'ha') for f in table.get(key, ()))
    befores, afters = names(app.before_request_funcs), names(app.after_request_funcs)
    return (befores == sorted(_STOOD_IN_FOR['before'])
            and afters == sorted(_STOOD_IN_FOR['after'])
            and not any(app.teardown_request_funcs.get(k) for k in (None, 'ha'))
            and not any(app.url_value_preprocessors.get(k) for k in (None, 'ha')))


class _LeaseFastPath:
    """The WSGI app in front of Flask: a renewal or a vote the Flask path would answer
    with 200 is answered here, everything else goes to `wsgi_app` as it came."""

    def __init__(self, app, wsgi_app, max_size):
        self.app, self.wsgi_app, self.max_size = app, wsgi_app, max_size
        self.hooks = _request_hooks(app)
        # a CORS setup puts headers on these answers too (flask-cors sends them without
        # an Origin): Flask's to make
        self.on = _hooks_known(app) and not g._cors_origins_env
        self.answered = 0
        self._after_made = {}

    def __call__(self, environ, start_response):
        kind = _LEASE_ROUTES.get(environ.get('PATH_INFO'))
        if (kind is not None and self.on and environ.get('REQUEST_METHOD') == 'POST'
                and _request_hooks(self.app) == self.hooks):
            resp = self._answer(environ, kind)
            if resp is not None:
                self.answered += 1
                return resp(environ, start_response)
        return self.wsgi_app(environ, start_response)

    def _answer(self, environ, kind):
        """The answer to a call that passes every check of the Flask path, None for any
        other (the Flask path judges it; a body read here is handed on with it)."""
        from pegaprox.core import ha, ha_wire
        import pegaprox.api.ha as ha_api
        from pegaprox.api.settings import ip_lists_pass
        from pegaprox.utils.audit import client_ip_from, _is_trusted_proxy
        get = environ.get
        length = get('CONTENT_LENGTH') or ''
        # the size, content-type and CSRF checks of validate_request, met the one way a
        # member's call meets them: JSON, X-Requested-With and neither Origin nor Referer
        if (get('QUERY_STRING') or get('SCRIPT_NAME') or get('HTTP_TRANSFER_ENCODING')
                or get('HTTP_UPGRADE') or get('HTTP_ORIGIN') or get('HTTP_REFERER')
                or get('HTTP_X_REQUESTED_WITH') != 'XMLHttpRequest'
                or 'application/json' not in (get('CONTENT_TYPE') or '')
                or (get('HTTP_ACCEPT_ENCODING') or 'identity').strip().lower() != 'identity'
                or not _LENGTH_RE.fullmatch(length)
                or not 0 < int(length) <= min(self.max_size, ha_api._MAX_PEER_BODY)):
            return None
        claimed = (get('HTTP_X_PEGAPROX_PEER') or '').partition(':')[0]
        digest = get('HTTP_X_PEGAPROX_PEER_BODY')
        rec = (ha._load().get('members') or {}).get(claimed)
        # a member we hold a key of: a paired instance, and no key recorded on the way
        if not rec or not rec.get('public_key') or not digest:
            return None
        path = environ['PATH_INFO']
        ip = client_ip_from(get('REMOTE_ADDR'),
                            lambda name: get('HTTP_' + name.upper().replace('-', '_')))
        # the lists let a member's signed call through here, or refuse it whatever it is
        if not ip_lists_pass(ip, path, lambda: True)[0]:
            return None
        n = int(length)
        try:
            body = environ['wsgi.input'].read(n)
        except (OSError, ValueError):
            # the caller went away: Flask finds the body short, as it would have
            body = b''
        environ['wsgi.input'] = io.BytesIO(body)
        # the digest the headers name is the one the rate limit's look before the body
        # checks the signature over (signed_member_call): the same call passes both
        if len(body) != n or digest != ha_wire.body_digest(body):
            return None
        verdict = ha.peer_verdict(EnvironHeaders(environ), 'POST', path, body)
        if verdict[0] != 'member' or not verdict[1].get('keyed'):
            environ[ha_api._PEER_VERDICT] = verdict
            return None
        https = get('wsgi.url_scheme') in ('https', 'wss') or (
            _is_trusted_proxy(get('REMOTE_ADDR')) and get('HTTP_X_FORWARDED_PROTO') == 'https')
        try:
            try:
                data = json.loads(body)
            except ValueError:
                data = None
            # api/ha.py _lease_call, as the route runs it, and jsonify's bytes
            out = self._json(ha.lease_request(verdict[1]['instance_id'], kind,
                                              data if isinstance(data, dict) else {}))
        except Exception:
            propagate = self.app.config['PROPAGATE_EXCEPTIONS']
            if propagate is None:
                propagate = self.app.testing or self.app.debug
            if propagate:
                raise
            self.app.logger.error(f'Exception on {path} [POST]', exc_info=True)
            from werkzeug.exceptions import InternalServerError
            resp = InternalServerError().get_response()
            for k, v in self._after(path, https):
                resp.headers[k] = v
            return resp
        # the headers of the answer as Flask's would come out (a header set through a
        # werkzeug Response cost more than the rest of the answer): its own two, then what
        # the after-request hooks put on in the order Flask runs them
        headers = [('Content-Type', self.app.json.mimetype), ('Content-Length', str(len(out)))]
        headers += self._after(path, https)

        def respond(environ, start_response):
            start_response('200 OK', headers)
            return [out]
        return respond

    def _json(self, obj):
        """The bytes jsonify() makes of `obj` (flask.json.provider DefaultJSONProvider)."""
        provider = self.app.json
        if (provider.compact is None and self.app.debug) or provider.compact is False:
            text = provider.dumps(obj, indent=2)
        else:
            text = provider.dumps(obj, separators=(',', ':'))
        return f'{text}\n'.encode()

    def _after(self, path, https):
        """What the after-request hooks add: the blueprint's mark that we hold the key,
        the app's security headers, flask-compress' Vary. The same for every call to a
        path, so made once, by the app's own add_security_headers on an empty answer
        (`https` stands for request.is_secure and a trusted proxy's X-Forwarded-Proto)."""
        key = (path, https)
        held = self._after_made.get(key)
        if held is None:
            from pegaprox.core import ha
            hook = next(f for f in self.app.after_request_funcs[None]
                        if f.__name__ == 'add_security_headers')
            blank = self.app.response_class()
            blank.headers.clear()
            scheme = 'https' if https else 'http'
            with self.app.test_request_context(path, method='POST', base_url=f'{scheme}://localhost',
                                               environ_base={'REMOTE_ADDR': '192.0.2.1'}):
                sec = list(hook(blank).headers.items())
            held = self._after_made[key] = ([(ha.PEER_KEYED_HEADER, '1')] + sec
                                            + [('Vary', 'Accept-Encoding')])
        return held


# MK Sep 2026 - the sweep this used to carry ran whenever the map passed 1024 entries
# and removed only EXPIRED windows. Keep the map just above the threshold with LIVE
# windows and you get a full scan on every single request that frees nothing: O(n) per
# request with n still climbing, which is a better attack than the one it was added to
# stop. The shared counter sweeps on a clock and evicts the oldest keys once the ceiling
# is genuinely breached, so neither the map nor the work per request can run away.
def _check_api_rate_limit(client_ip: str) -> bool:
    """Simple sliding window rate limiter."""
    if API_RATE_LIMIT <= 0:
        return True
    return g.api_rate_window.allow(client_ip)


def download_static_files():
    """Download all required static files for offline operation.
    
    MK: Jan 2027 - Security: All downloaded JavaScript, CSS, and font files are now
    verified against expected SHA-384 hashes before being persisted to disk. This
    prevents execution of tampered or substituted code if a CDN or upstream package
    repository is compromised. The hashes must be manually updated whenever package
    versions change, ensuring deliberate version control of all third-party assets.
    """
    import urllib.request
    import re as _re
    import hashlib

    print("=" * 60)
    print("PegaProx Static Files Downloader")
    print("=" * 60)
    print()

    # MK: Jan 2027 - Subresource Integrity: expected SHA-384 hashes for all downloaded assets.
    # These digests pin the exact artifact version and prevent execution of tampered or
    # substituted code. Update these hashes whenever the upstream package versions change.
    # To generate: curl -sL <URL> | openssl dgst -sha384 -binary | openssl base64 -A
    EXPECTED_HASHES = {
        'react.production.min.js': 'sha384-qJEu4RdgvlqNmS8c/6F8xGKz8LqZhLxLlKQvLlKQvLlKQvLlKQvLlKQvLlKQvLlK',  # MUST UPDATE
        'react-dom.production.min.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
        'babel.min.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
        'chart.umd.min.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
        'xterm.min.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
        'xterm-addon-fit.min.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
        'xterm.min.css': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',  # MUST UPDATE
    }

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
            
            # MK: Jan 2027 - Integrity check: refuse to persist unverified artifacts
            expected_hash = EXPECTED_HASHES.get(filename)
            if not expected_hash or 'PLACEHOLDER' in expected_hash:
                print(f"FAILED: No valid integrity hash defined for {filename}")
                print(f"         Define the expected SHA-384 hash in EXPECTED_HASHES before downloading.")
                failed += 1
                continue
            
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                    data = response.read()
                
                # MK: Jan 2027 - Verify integrity before persisting to disk
                computed_hash = hashlib.sha384(data).digest()
                import base64
                computed_b64 = base64.b64encode(computed_hash).decode('ascii')
                computed_sri = f'sha384-{computed_b64}'
                
                if computed_sri != expected_hash:
                    print(f"FAILED: Integrity check failed")
                    print(f"         Expected: {expected_hash}")
                    print(f"         Got:      {computed_sri}")
                    print(f"         The downloaded file does not match the expected hash.")
                    print(f"         This may indicate tampering, CDN compromise, or version mismatch.")
                    failed += 1
                    continue
                
                with open(dest, 'wb') as f:
                    f.write(data)
                print(f"OK ({len(data):,} bytes, integrity verified)")
                success += 1
            except Exception as e:
                print(f"FAILED: {e}")
                failed += 1

    # MK: Mar 2026 - tailwind.min.css is now a full CLI build, don't overwrite it (#118)
    if os.path.exists('static/css/tailwind.min.css'):
        sz = os.path.getsize('static/css/tailwind.min.css')
        print(f"\n  tailwind.min.css already exists ({sz:,} bytes), skipping")
        print("  (rebuild with: npx tailwindcss -i input.css -o static/css/tailwind.min.css --minify)")
    else:
        print("\n  WARNING: static/css/tailwind.min.css missing!")
        print("  Run: npx tailwindcss -i input.css -o static/css/tailwind.min.css --minify")
        failed += 1

    # LW: Mar 2026 - download Google Fonts for offline (#118)
    # MK: Jan 2027 - Add integrity hashes for font files
    print("\nDownloading Google Fonts for offline use...")
    os.makedirs('static/fonts', exist_ok=True)

    # MK: Jan 2027 - Expected SHA-384 hashes for font files
    FONT_HASHES = {
        'plus-jakarta-sans-400.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'plus-jakarta-sans-500.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'plus-jakarta-sans-600.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'plus-jakarta-sans-700.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'plus-jakarta-sans-****0.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'jetbrains-mono-400.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'jetbrains-mono-500.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'jetbrains-mono-600.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'jetbrains-mono-700.woff2': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
    }

    _gfonts = {
        'plus-jakarta-sans': {
            'family': 'Plus Jakarta Sans',
            'weights': {
                '400': 'https://fonts.gstatic.com/s/plusjakartasans/v8/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_KU7NShXUEKi4Rw.woff2',
                '500': 'https://fonts.gstatic.com/s/plusjakartasans/v8/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_AU7NShXUEKi4Rw.woff2',
                '600': 'https://fonts.gstatic.com/s/plusjakartasans/v8/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_zUnNShXUEKi4Rw.woff2',
                '700': 'https://fonts.gstatic.com/s/plusjakartasans/v8/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_9EnNShXUEKi4Rw.woff2',
                '****0': 'https://fonts.gstatic.com/s/plusjakartasans/v8/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_KUnNShXUEKi4Rw.woff2',
            }
        },
        'jetbrains-mono': {
            'family': 'JetBrains Mono',
            'weights': {
                '400': 'https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKxjPVmUsaaDhw.woff2',
                '500': 'https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8-axjPVmUsaaDhw.woff2',
                '600': 'https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8FapjPVmUsaaDhw.woff2',
                '700': 'https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8LapjPVmUsaaDhw.woff2',
            }
        }
    }

    font_css = "/* LW: Mar 2026 - local Google Fonts for offline mode (#118) */\n"
    for font_id, font_info in _gfonts.items():
        for weight, url in font_info['weights'].items():
            fname = f"{font_id}-{weight}.woff2"
            dest = f"static/fonts/{fname}"
            print(f"  {fname}...", end=' ')
            
            # MK: Jan 2027 - Verify font file integrity
            expected_hash = FONT_HASHES.get(fname)
            if not expected_hash or 'PLACEHOLDER' in expected_hash:
                print(f"FAILED: No valid integrity hash defined for {fname}")
                failed += 1
                continue
            
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                    data = response.read()
                
                # MK: Jan 2027 - Verify integrity before persisting
                computed_hash = hashlib.sha384(data).digest()
                import base64
                computed_b64 = base64.b64encode(computed_hash).decode('ascii')
                computed_sri = f'sha384-{computed_b64}'
                
                if computed_sri != expected_hash:
                    print(f"FAILED: Integrity check failed")
                    print(f"         Expected: {expected_hash}")
                    print(f"         Got:      {computed_sri}")
                    failed += 1
                    continue
                
                with open(dest, 'wb') as f:
                    f.write(data)
                print(f"OK ({len(data):,} bytes, integrity verified)")
                success += 1
            except Exception as e:
                print(f"FAILED: {e}")
                failed += 1

            font_css += f"""@font-face {{
  font-family: '{font_info['family']}';
  font-style: normal;
  font-weight: {weight};
  font-display: swap;
  src: url('/static/fonts/{fname}') format('woff2');
}}
"""

    try:
        with open('static/css/fonts.css', 'w') as f:
            f.write(font_css)
        print("  fonts.css... OK")
        success += 1
    except Exception as e:
        print(f"  fonts.css... FAILED: {e}")
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

    # MK: Jan 2027 - Expected SHA-384 hashes for noVNC files (before import rewriting)
    # These must be computed from the original CDN files before any transformation
    NOVNC_HASHES = {
        'core/rfb.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/display.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/inflator.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/deflator.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/websock.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/encodings.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/des.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/ra2.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/base64.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/copyrect.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/hextile.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/raw.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/rre.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/tight.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/tightpng.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/zrle.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/decoders/jpeg.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/keyboard.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/keysym.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/keysymdef.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/gesturehandler.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/domkeytable.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/util.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/vkeys.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/xtscancodes.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/input/fixedkeys.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/browser.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/cursor.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/element.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/events.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/eventtarget.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/int.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/logging.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/strings.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'core/util/md5.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/inflate.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/zstream.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/deflate.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/messages.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/trees.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/adler32.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/crc32.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/inffast.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/zlib/inftrees.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
        'vendor/pako/lib/utils/common.js': 'sha384-PLACEHOLDER_HASH_MUST_BE_UPDATED_BEFORE_USE',
    }

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
        
        # MK: Jan 2027 - Verify integrity before transformation
        expected_hash = NOVNC_HASHES.get(filepath)
        if not expected_hash or 'PLACEHOLDER' in expected_hash:
            print(f"FAILED: No valid integrity hash defined for {filepath}")
            novnc_failed += 1
            failed += 1
            continue
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                raw_bytes = response.read()
            
            # MK: Jan 2027 - Verify integrity of original file before any transformation
            computed_hash = hashlib.sha384(raw_bytes).digest()
            import base64
            computed_b64 = base64.b64encode(computed_hash).decode('ascii')
            computed_sri = f'sha384-{computed_b64}'
            
            if computed_sri != expected_hash:
                print(f"FAILED: Integrity check failed")
                print(f"         Expected: {expected_hash}")
                print(f"         Got:      {computed_sri}")
                novnc_failed += 1
                failed += 1
                continue
            
            # Integrity verified, now decode and transform
            content = raw_bytes.decode('utf-8')

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
            print("OK (integrity verified)")
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


def _path_diagnostics(path):
    """owner/mode of a path and of its parent, plus who we are.

    #633: the operator needs to compare the two. The whole bug was a cert the
    service user could not reach, and the log said nothing about who owned it.
    """
    try:
        import pwd
        import grp
    except ImportError:      # non-POSIX, ids only
        pwd = grp = None

    def _name(getter, attr, num):
        if getter is None:
            return str(num)
        try:
            return getattr(getter(num), attr)
        except (KeyError, OSError):
            return str(num)

    lines = []
    target = os.path.abspath(path)
    for p in (target, os.path.dirname(target)):
        try:
            st = os.stat(p)
            lines.append("  %s owner=%s:%s mode=0o%03o" % (
                p,
                _name(pwd and pwd.getpwuid, 'pw_name', st.st_uid),
                _name(grp and grp.getgrgid, 'gr_name', st.st_gid),
                stat.S_IMODE(st.st_mode)))
        except OSError as e:
            lines.append("  %s cannot stat: %s" % (p, e.strerror))
    lines.append("  this process uid=%s(%s) gid=%s(%s)" % (
        os.geteuid(), _name(pwd and pwd.getpwuid, 'pw_name', os.geteuid()),
        os.getegid(), _name(grp and grp.getgrgid, 'gr_name', os.getegid())))
    return "\n".join(lines)


def _tls_setup_failed(reason, path):
    """Fail closed, or return None if plaintext was asked for explicitly.

    #633: this used to print a WARNING and fall through with ssl_context=None,
    which bound cleartext HTTP on the port that was meant to be TLS. TLS clients
    then got "Invalid http version: '\\x16\\x03\\x01...'" and the dashboard was
    down while the service looked healthy. A downgrade has to be a decision, not
    an accident.
    """
    detail = "TLS is enabled but there is no usable certificate: %s\n%s" % (
        reason, _path_diagnostics(path))
    if os.environ.get('PEGAPROX_ALLOW_PLAINTEXT', '').strip().lower() in ('1', 'true', 'yes', 'on'):
        logging.getLogger(__name__).error(
            "%s\n  PEGAPROX_ALLOW_PLAINTEXT is set, so serving PLAINTEXT HTTP on the "
            "TLS port anyway - every TLS client will fail against it.", detail)
        return None
    raise SystemExit(
        "%s\n  Refusing to serve plaintext on the TLS port. Fix the certificate, or put "
        "PegaProx behind a reverse proxy (the reverse_proxy setting), or set "
        "PEGAPROX_ALLOW_PLAINTEXT=1 to serve cleartext there on purpose." % detail)


def _unreadable(path):
    """The OSError from opening path, or None if it opens fine.

    os.path.exists() is not enough: it is False for a cert in a directory we
    cannot search, which is how EACCES ended up in the "no certificates" branch
    and got a valid cert overwritten (#633).
    """
    try:
        with open(path, 'rb'):
            return None
    except OSError as e:
        return e


def _unloadable(cert_file, key_file):
    """The exception from actually loading the cert+key into an SSL context, or
    None if the pair parses.

    MK #633 follow-up (adversarial review of #637): readable != loadable. A
    truncated, empty, corrupt or mismatched cert/key opens fine (so _unreadable
    says it's ok) but blows up later at ssl_ctx.load_cert_chain() as an UNCAUGHT
    ssl.SSLError - a raw traceback instead of the actionable message, for what is
    the most common non-permission cert failure. Load it here so a bad-but-present
    pair routes through the same fail-closed path as a missing one.
    """
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_file, key_file)
        return None
    except (ssl.SSLError, OSError, ValueError) as e:
        return e


def _generate_self_signed(cert_file, key_file, domain, app_name):
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


def _resolve_ssl_context(reverse_proxy, domain='', app_name='PegaProx',
                         cert_file=SSL_CERT_FILE, key_file=SSL_KEY_FILE):
    """(cert, key) for the TLS listener, or None for plaintext.

    Posture (#633): TLS unless a reverse proxy terminates it for us. If TLS is
    the posture and we cannot load or generate a usable pair, we do not come up.
    """
    if reverse_proxy:
        return None      # nginx/haproxy/traefik owns TLS, plain HTTP on the bind

    cert_err, key_err = _unreadable(cert_file), _unreadable(key_file)
    if cert_err is None and key_err is None:
        # MK #633 follow-up: readable isn't enough - a corrupt/mismatched pair has
        # to fail here with a clear reason, not crash later at load_cert_chain.
        bad = _unloadable(cert_file, key_file)
        if bad is not None:
            return _tls_setup_failed(
                "%s and %s are present but do not load as a cert/key pair: %s"
                % (cert_file, key_file, bad), cert_file)
        print("SSL certificates found - starting with HTTPS")
        return (cert_file, key_file)

    # Present but not readable is NOT "missing". Never generate over it - that
    # would report the wrong problem, and destroy a working cert if the write
    # happened to succeed.
    for path, err in ((cert_file, cert_err), (key_file, key_err)):
        if err is not None and err.errno != errno.ENOENT:
            return _tls_setup_failed("cannot read %s: %s" % (path, err.strerror), path)

    # MK #633 follow-up: only a genuinely empty pair (BOTH missing) may be
    # generated. If one half is present and only the other is ENOENT, generation
    # would clobber the surviving half - so fail closed and name the missing one.
    if cert_err is None or key_err is None:
        present, missing = (cert_file, key_file) if key_err is not None else (key_file, cert_file)
        return _tls_setup_failed(
            "%s is present but its counterpart %s is missing - refusing to regenerate "
            "over the existing half" % (present, missing), missing)

    # MK 2026-06-08 (#531): generate into the persisted config/ssl dir, and
    # create the dir first - on a fresh container the old target did not exist,
    # generation failed with ENOENT and we fell back to plain HTTP.
    print("No SSL certificates found. Generating self-signed certificate...")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cert_file)), exist_ok=True)
        _generate_self_signed(cert_file, key_file, domain, app_name)
    except ImportError:
        return _tls_setup_failed("pyOpenSSL is not installed (pip install pyOpenSSL)", cert_file)
    except Exception as e:
        return _tls_setup_failed("could not generate one: %s" % e, cert_file)
    bad = _unloadable(cert_file, key_file)
    if bad is not None:      # a generator that emits a pair we can't load is a bug, not plaintext
        return _tls_setup_failed("generated a certificate that will not load: %s" % bad, cert_file)
    print("Self-signed certificate generated: %s" % cert_file)
    return (cert_file, key_file)


def _start_managers(config, only=None):
    """Cluster managers (Proxmox and XCP-ng) for `config` as load_config() returns it,
    then the PBS and ESXi servers and the ESXi hosts XHM treats as clusters.

    The same in every role: on a standby with the live view they start as well and
    only read, since everything in them that acts asks ha.is_active() first. A standby
    that reloads some of them (ha.reload_managers) passes those clusters in `config`
    and the servers in `only`, as 'pbs:<id>' and 'vmware:<id>'; None is every server."""
    from pegaprox.core.pbs import load_pbs_servers
    from pegaprox.core.vmware import load_vmware_servers
    from pegaprox.models.tasks import PegaProxConfig
    from pegaprox.core.manager import PegaProxManager

    for cluster_id, cluster_data in config.items():
        config_obj = PegaProxConfig(cluster_data)
        ctype = cluster_data.get('cluster_type', 'proxmox')
        if ctype == 'xcpng':
            from pegaprox.core.xcpng import XcpngManager
            manager = XcpngManager(cluster_id, config_obj)
            manager.start()
            g.cluster_managers[cluster_id] = manager
            print(f"Started XCP-ng manager for pool: {cluster_data['name']}")
        else:
            manager = PegaProxManager(cluster_id, config_obj)
            manager.start()
            g.cluster_managers[cluster_id] = manager
            print(f"Started PegaProx manager for cluster: {cluster_data['name']}")

    pbs_ids = vmw_ids = None
    if only is not None:
        pbs_ids = {key[4:] for key in only if key.startswith('pbs:')}
        vmw_ids = {key[7:] for key in only if key.startswith('vmware:')}
        if not pbs_ids and not vmw_ids:
            return

    try:
        load_pbs_servers(only=pbs_ids)
    except Exception as e:
        logging.warning(f"Failed to load PBS servers at startup: {e}")

    try:
        load_vmware_servers(only=vmw_ids)
        # NS: register ESXi hosts as XHM-capable clusters
        from pegaprox.core.esxi_cluster import ESXiClusterManager
        for vmw_id, vmw_mgr in list(g.vmware_managers.items()):
            if vmw_ids is not None and vmw_id not in vmw_ids:
                continue
            if getattr(vmw_mgr, 'server_type', '') == 'esxi':
                g.cluster_managers[vmw_id] = ESXiClusterManager(vmw_id, vmw_mgr)
                logging.info(f"Registered ESXi host '{vmw_mgr.name}' as XHM cluster {vmw_id}")
    except Exception as e:
        logging.warning(f"Failed to load VMware servers at startup: {e}")


def main(debug_mode=False):
    """Main entry point - starts PegaProx server."""
    from pegaprox.utils.auth import (load_users, load_sessions, backfill_initialized_marker,
                                     initialization_state, INIT_UNINITIALIZED, INIT_UNKNOWN)
    from pegaprox.utils.audit import load_audit_log
    from pegaprox.core.config import load_config
    from pegaprox.background.broadcast import start_broadcast_thread
    from pegaprox.background.alerts import start_alert_thread
    from pegaprox.background.scheduler import start_scheduler_thread
    from pegaprox.background.password_expiry import start_password_expiry_thread
    from pegaprox.background.cross_cluster_lb import start_cross_cluster_lb_thread
    from pegaprox.background.cross_cluster_replication import start_cross_cluster_replication_thread
    from pegaprox.background.syslog_server import start_syslog_server
    from pegaprox.api.schedules import start_scheduler as start_actions_scheduler
    from pegaprox.api.helpers import load_server_settings, acme_dns_config_from_settings
    from pegaprox.utils.rbac import get_pool_membership_cache
    from pegaprox.constants import AUDIT_RETENTION_DAYS

    # Initialize SSH semaphore
    g.init_ssh_semaphore(SSH_MAX_CONCURRENT)

    # Configure logging
    # MK May 2026 (#357): env-var override (PEGAPROX_LOG_LEVEL) wins over default
    # but --debug still forces DEBUG so the troubleshooting path doesn't need an
    # extra knob. Unset env + no --debug → previous WARNING default.
    from pegaprox.constants import LOG_LEVEL as _ENV_LOG_LEVEL
    if debug_mode:
        log_level = logging.DEBUG
    elif _ENV_LOG_LEVEL is not None:
        log_level = _ENV_LOG_LEVEL
    else:
        log_level = logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s' if debug_mode else '%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # MK Sep 2026 - CWE-117 at the sink. Names, URLs and error strings the caller chose
    # reach log lines all over this tree; CR/LF forges a line and ESC repaints the
    # operator's terminal. Guarding the call sites means seventy-five edits and a
    # seventy-sixth somebody forgets, so it goes on the handlers instead. Tracebacks
    # arrive via exc_info and keep their newlines.
    # MK Sep 2026 (follow-up) - the handler filter alone missed the per-cluster loggers
    # in core/manager.py and core/xcpng.py: their handlers are attached when a cluster is
    # constructed, long after this runs, and a cluster logger writes through its own
    # handlers before propagating here. The record factory sanitises at construction, so
    # it covers loggers that do not exist yet. Both stay: the filter is harmless and the
    # sanitiser is idempotent.
    from pegaprox.utils.sanitization import (install_log_injection_filter,
                                             install_log_record_sanitizer)
    install_log_record_sanitizer()
    install_log_injection_filter()

    if not debug_mode:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        logging.getLogger('gevent').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)

    # MK Oct 2026 (#625) - one process per config directory, before anything here writes
    # to it (the DB encryption below already does). A second one - started by hand next
    # to the service, say - shares the database and the HA state and acts next to it.
    from pegaprox.core import ha
    try:
        # and never on the state directory of a witness (pegaprox/witness.py)
        ha.check_not_a_witness_dir()
        ha.lock_config_dir()
    except ha.HaError as e:
        print(f"\n[FATAL] {e}\n")
        sys.exit(1)

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

    try:
        import XenAPI
        print("  ✓ XenAPI (XCP-ng integration)")
    except ImportError:
        print("  ✗ XenAPI - XCP-ng clusters disabled (pip install XenAPI)")

    if missing_libs:
        print(f"\n  Install missing: pip install {' '.join(missing_libs)}")
    print()

    # NS May 2026 — auto-encrypt every DB under CONFIG_DIR on first boot if
    # sqlcipher3 is available. MUST run BEFORE create_app(): plugin loader +
    # push-inbox initialiser open DB connections inside create_app(), so by
    # the time we'd hit the post-create_app point it's already too late and
    # SQLCipher fails the PRAGMA key handshake against a plain file.
    # Idempotent on subsequent boots (state == 'encrypted' short-circuits).
    #
    # Covers pegaprox.db (main) + syslog.db (Apr 2026 syslog server) — both
    # get opened through dbcrypto.connect() so both must be encrypted in lock-
    # step. ensure_db_encrypted() handles 'missing' state cleanly (noop) so
    # only-pegaprox-no-syslog deployments are fine.
    try:
        from pegaprox.core import dbcrypto as _dbcrypto
        from pegaprox.constants import CONFIG_DIR as _CFGDIR
        for _db_name in ('pegaprox.db', 'syslog.db'):
            _db_path = os.path.join(_CFGDIR, _db_name)
            _r = _dbcrypto.ensure_db_encrypted(_db_path)
            if _r.get('action') == 'migrated':
                print(f"  ✓ {_db_name} auto-encrypted ({_r['rows_copied']} rows, {_r['duration_s']}s)")
                print(f"    backup: {_r['backup_path']}")
            elif _r.get('action') == 'no-backend':
                print(f"  ⚠ sqlcipher3 not installed — {_db_name} stays plain (field-level Fernet still active)")
    except RuntimeError as _e:
        # corrupt / unknown-key — refuse to start
        print(f"\n[FATAL] {_e}\n")
        sys.exit(1)
    except Exception as _e:
        # don't take down boot for a non-fatal hiccup — log and continue
        logging.error(f"[DBCRYPTO] auto-encrypt check failed: {_e}", exc_info=True)

    # MK Sep 2026 (#625) - an active that was down while its standby got promoted still
    # reads "active" from its own state file. Ask the peer once, before anything here
    # can act on the clusters with the configuration from before the outage: create_app()
    # below is the first thing that starts threads (importing the blueprints starts the
    # storage balancer at module import, register_blueprints the drift and multi-SDN
    # scanners, the SIEM worker and the snapshot scheduler), and the managers and the
    # other loops come after that. If the peer holds a newer epoch this steps down to
    # standby without a restart, so the role read further down is already the right one.
    # An unreachable peer changes nothing: every acting loop started below checks
    # ha.is_active() on each tick, so it stops the moment the ha loop steps us down.
    # The markers go first: a member whose state file is gone comes up passive.
    # In an automatic group the same call asks for the lease instead (ha.lease_boot): a
    # leader on disk renews with its majority here or goes on as a standby, and what
    # starts once below goes by ha.acting_process().
    _ha_markers = ha.check_markers_at_boot()
    if _ha_markers == 'missing':
        print("HA state file missing on a group member - staying passive until it is restored or unpaired")
    try:
        _ha_boot = ha.check_peer_at_boot(timeout=5)
    except Exception as e:
        _ha_boot = f'check failed: {e}'
    logging.info(f"[HA] boot check: {_ha_boot} (role {ha.role()}, epoch {ha.epoch()})")
    if ha.role() != ha.ROLE_STANDALONE or ha.peer():
        print(f"HA role at boot: {ha.role()}, epoch {ha.epoch()} ({_ha_boot})")

    # Create Flask app (plugins + push inbox will hit the DB here)
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

    # MK May 2026 — backfill initialized marker for upgrades from pre-setup-wizard
    # builds (pre-init installs already had users; we just stamp the marker so the
    # /login path's is_initialized() doesn't fall through to NOT_INITIALIZED).
    backfill_initialized_marker()

    _init_state = initialization_state()
    if _init_state == INIT_UNINITIALIZED:
        print("\n" + "=" * 50)
        print("FIRST-RUN SETUP REQUIRED")
        print("  No admin account exists yet — open the PegaProx URL")
        print("  in a browser to create the first administrator via the")
        print("  setup wizard. /api/auth/login is disabled until that")
        print("  is done.")
        print("=" * 50 + "\n")
    elif _init_state == INIT_UNKNOWN:
        # not a fresh install - the store simply did not answer. Both login and
        # setup refuse in this state, so say which one the operator is looking at.
        print("\n" + "=" * 50)
        print("USER STORE UNREADABLE")
        print("  Could not read the user table. Login and the setup wizard")
        print("  are BOTH refused until this is resolved - check the")
        print("  encryption key and the permissions on config/.")
        print("=" * 50 + "\n")

    # MK Sep 2026 (#625) - a standby holds the configuration and acts on none of it.
    # The role is read once: every role change restarts the process, and so does a
    # change of the live view or of how the managers connect.
    standby = ha.is_standby()
    live_managers = ha.managers_wanted()

    if standby and live_managers:
        # the live view: the managers start here too and only read. One short pull
        # first, so they start from the active's configuration of now - starting from
        # the one this instance stopped with would restart it right after the first sync.
        _ha_pull = ha.boot_pull(timeout=10)
        logging.warning(f"[HA] standby with the live view: cluster, PBS and ESXi managers start "
                        f"read-only, nothing acts from here (sync at start: {_ha_pull})")
    elif standby:
        logging.warning("[HA] standby, live view off: no cluster, PBS or ESXi managers are "
                        "started - they stay down until this instance is promoted or the "
                        "live view is switched on")

    # Load existing configuration
    config = load_config()

    if live_managers:
        _start_managers(config)
        try:
            ha.note_managers_started(ha.manager_signature())
        except Exception as e:
            # without a baseline a standby never restarts for new connection settings
            logging.warning(f"[HA] could not note what the managers started from: {e}")

    # Start background threads
    start_broadcast_thread()
    print("Started WebSocket live updates broadcast thread")

    start_alert_thread()
    print("Started alert monitoring thread")

    start_scheduler_thread()
    print("Started task scheduler thread")

    # NS: Mar 2026 - the scheduled_actions scheduler (UI-created schedules, #134)
    # background/scheduler.py only handles the old scheduled_tasks table
    start_actions_scheduler()
    print("Started scheduled actions thread")

    start_password_expiry_thread()
    print("Started password expiry check thread")

    start_cross_cluster_lb_thread()
    print("Started cross-cluster load balancer thread")

    start_cross_cluster_replication_thread()
    print("Started cross-cluster replication scheduler thread")

    # MAC addresses, notes and configured IPs for the search; the loop itself only reads
    # where users are served
    from pegaprox.background.guest_index import start_guest_index_thread
    start_guest_index_thread()
    print("Started guest search index thread")

    try:
        start_syslog_server()
        print("Started integrated syslog server")
    except Exception as e:
        logging.warning(f"Syslog server failed to start: {e}")

    # #625: not on a standby - the plans are the active's, and so is any run in flight.
    # The reset of DR plans a crash left running or testing (#238) is start_heartbeat's
    # recover_orphan_runs, which asks ha.is_active() right before it writes. A copy of
    # it here wrote on the role read once above.
    if not standby:
        from pegaprox.background.site_recovery import start_heartbeat
        start_heartbeat()
        print("Started site recovery heartbeat monitor")

        # Start plugin background tasks
        from pegaprox.api.plugins import start_plugin_backgrounds
        start_plugin_backgrounds()

    # #625: pulls from the active on a standby, watches the peer on an active,
    # idles while unpaired
    ha.start_loop()

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

    # MK: Mar 2026 - ACME auto-renewal thread (#96)
    def acme_renewal_loop():
        time.sleep(30)  # wait for server to fully start
        while True:
            try:
                _settings = load_server_settings()
                if _settings.get('acme_enabled') and _settings.get('domain'):
                    from pegaprox.core.acme import check_and_renew
                    # #725 (nvaert1986) — renew INTO the dir the TLS listener loads
                    # from (config/ssl). The old heuristic wrote to the retired
                    # <root>/ssl, so a renewed cert was issued but never served.
                    _ssl = SSL_DIR
                    _challenge_type = _settings.get('acme_challenge_type') or 'http-01'
                    _dns_provider = _settings.get('acme_dns_provider') or 'manual'
                    renewed = check_and_renew(
                        _settings['domain'], _settings.get('acme_email', ''),
                        _ssl, staging=_settings.get('acme_staging', False),
                        directory_url=_settings.get('acme_directory_url', ''),
                        challenge_type=_challenge_type,
                        dns_provider=_dns_provider,
                        dns_config=acme_dns_config_from_settings(_settings)
                    )
                    if renewed:
                        logging.info("[ACME] Certificate renewed, restart required for new cert")
            except Exception as e:
                logging.debug(f"[ACME] Renewal check error: {e}")
            time.sleep(86400)  # check once per day

    threading.Thread(target=acme_renewal_loop, daemon=True).start()
    print("Started ACME auto-renewal thread")

    # Load server settings
    server_settings = load_server_settings()
    port = server_settings.get('port', 5000)
    bind_host = os.environ.get('PEGAPROX_HOST')

    # NS Mar 2026 - reverse proxy mode: skip SSL, bind localhost, trust proxy headers
    reverse_proxy = server_settings.get('reverse_proxy_enabled', False)
    if os.environ.get('PEGAPROX_BEHIND_PROXY', '').lower() in ('1', 'true', 'yes'):
        reverse_proxy = True

    # load trusted proxy IPs for X-Forwarded-For (loopback always trusted)
    from pegaprox.utils.audit import load_trusted_proxies
    trusted = os.environ.get('PEGAPROX_TRUSTED_PROXIES', '') or server_settings.get('trusted_proxies', '')
    load_trusted_proxies(trusted)
    if trusted:
        print(f"Trusted proxies: {trusted}")

    if not bind_host:
        if reverse_proxy:
            custom_bind = server_settings.get('proxy_bind_address', '').strip()
            if custom_bind:
                bind_host = custom_bind
                print(f"Reverse proxy mode — custom bind: {bind_host}")
            else:
                bind_host = '127.0.0.1'
                print("Reverse proxy mode — binding to 127.0.0.1 only")
        elif _test_ipv6_available():
            bind_host = '::'
            print("IPv6 available — binding dual-stack (::)")
        else:
            bind_host = '0.0.0.0'
            print("IPv6 not available — binding IPv4 only (0.0.0.0)")
    else:
        if ':' in bind_host and not _test_ipv6_available():
            print(f"WARNING: IPv6 bind address '{bind_host}' requested but IPv6 not available")
            print("Falling back to 0.0.0.0")
            bind_host = '0.0.0.0'

    # Publish the resolved listen address for anything that has to reach us from
    # this host later (see globals.SERVER_BIND_HOST). MK Sep 2026 (#957)
    g.SERVER_BIND_HOST = bind_host
    g.SERVER_BIND_PORT = port

    # MK: when behind proxy, SSL is handled by nginx/haproxy - we run plain HTTP
    #
    # MK Aug 2026: we deliberately do NOT gate on the `ssl_enabled` setting here.
    # The pre-#633 code only ever used it as a fast path - its else-branch generated
    # a cert and served HTTPS regardless - so with the toggle off (which is the
    # api/helpers.py default) every existing install is in fact running TLS. Honouring
    # it now would silently downgrade all of them to cleartext on upgrade. Posture
    # stays "TLS unless a reverse proxy terminates it"; wiring the toggle up properly
    # is its own change (#638).
    domain = server_settings.get('domain', '')
    app_name = server_settings.get('app_name', 'PegaProx')
    if reverse_proxy:
        print("SSL disabled (handled by reverse proxy)")

    # Check for SSL certificates (skipped entirely behind a reverse proxy).
    # MK Aug 2026 (#633): this fails closed now - see _resolve_ssl_context(). It used
    # to warn and fall through to plain HTTP on the port that was supposed to be TLS.
    ssl_context = _resolve_ssl_context(reverse_proxy, domain, app_name)

    # Start HTTP redirect server if SSL is enabled (not needed behind reverse proxy)
    http_redirect_port = server_settings.get('http_redirect_port', 0)
    if http_redirect_port == 0:
        http_redirect_port = **** if os.geteuid() == 0 else -1
    http_redirect_port = int(os.environ.get('PEGAPROX_HTTP_PORT', http_redirect_port))

    if ssl_context and http_redirect_port > 0 and not reverse_proxy:
        redirect_thread = threading.Thread(
            target=_start_http_redirect,
            args=(bind_host, http_redirect_port, port, domain),
            daemon=True
        )
        redirect_thread.start()
        print(f"Started additional HTTP -> HTTPS redirect on port {http_redirect_port}")

    # Determine workers
    # MK 2026-05-31 (v2) — auto-scale with CPU, no hardcoded cap.
    # Two-part fix:
    #   (1) `workers` was previously just a log-label — _start_gevent_server
    #       prints "(N greenlets)" but never passed `spawn=Pool(N)` to
    #       WSGIServer, so the server actually spawned UNLIMITED greenlets.
    #       Now plumbed through (see _start_gevent_server below).
    #   (2) Formula changed: `min(cpu_count*2, 16)` capped huge customer
    #       boxes at 16. `max(8, cpu_count * 4)` gives:
    #           1c VM:   8 workers
    #           4c:     16 workers (same as old default)
    #           8c:     32 workers
    #           32c:   128 workers
    #       gevent greenlets are extremely cheap (a few KB stack) so 100s
    #       per request handler are fine; the I/O-bound workload benefits
    #       from a generous pool when /health + /vms-backup-status + a
    #       dashboard refresh all fire at the same time.
    # NS 2026-06-05 — raised floor + multiplier: EACH live SSE/WebSocket stream
    # holds a pool slot for its whole lifetime, so max(8, cpu*4) (=16 on a 4c
    # box) could be consumed by ~16 open dashboard tabs and starve all other API
    # traffic (root of #526's "health spammed, absurdly large time"). Greenlets
    # are cheap so a big pool is fine. Still PEGAPROX_WORKERS-overridable.
    #           1c VM: 32    4c: 64    8c: 128    32c: 512
    cpu_count = multiprocessing.cpu_count()
    workers = int(os.environ.get('PEGAPROX_WORKERS', max(32, cpu_count * 16)))

    print(f"System: {cpu_count} CPU cores detected")
    print(f"Memory optimization: Garbage collection tuned for {workers} workers")
    gc.set_threshold(700, 10, 10)

    # Start with Gevent if available
    use_gevent = os.environ.get('PEGAPROX_SERVER', 'auto').lower()

    if use_gevent == 'gevent' or (use_gevent == 'auto' and GEVENT_AVAILABLE):
        if GEVENT_AVAILABLE:
            _start_gevent_server(app, bind_host, port, ssl_context, domain, workers, http_redirect_port)
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
    """Start VNC and SSH WebSocket servers on port+1 and port+2.

    Returns the SSH WebSocket subprocess (a Popen) so the caller can terminate it on
    shutdown. The VNC server is a daemon thread and needs no handle; the SSH server is a
    long-running asyncio subprocess that would otherwise outlive us. (#7****)"""
    vnc_ws_port = port + 1
    ssh_ws_port = port + 2

    try:
        from pegaprox.api.vms import start_vnc_websocket_server, start_ssh_websocket_server
    except ImportError as e:
        print(f"WARNING: Console WebSocket servers not available: {e}")
        return None

    # NS Feb 2026 - asyncio/websockets creates IPv6-only socket for '::' (#95)
    # Use '' so asyncio binds to ALL interfaces (creates both IPv4 + IPv6 listeners)
    console_host = '' if bind_host == '::' else bind_host

    # MK Feb 2026 - start each server independently so one failure doesn't block the other
    ssh_proc = None
    for name, start_fn, ws_port in [
        ("VNC", start_vnc_websocket_server, vnc_ws_port),
        ("SSH", start_ssh_websocket_server, ssh_ws_port),
    ]:
        try:
            if ssl_context:
                result = start_fn(ws_port, ssl_cert=ssl_context[0], ssl_key=ssl_context[1], host=console_host)
            else:
                result = start_fn(ws_port, host=console_host)
            # only the SSH server hands back a live subprocess
            if name == "SSH" and result is not None:
                ssh_proc = result
        except Exception as e:
            print(f"ERROR: {name} WebSocket server (port {ws_port}) failed to start: {e}")
            logging.error(f"{name} WebSocket server startup failed: {e}", exc_info=True)

    return ssh_proc


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

                    # MK: Mar 2026 - serve ACME challenges on port **** instead of redirecting (#96)
                    if path.startswith('/.well-known/acme-challenge/'):
                        acme_token = path.split('/')[-1]
                        from pegaprox.core.acme import get_challenge_response
                        challenge_resp = get_challenge_response(acme_token)
                        if challenge_resp:
                            http_resp = (
                                f"HTTP/1.1 200 OK\r\n"
                                f"Content-Type: text/plain\r\n"
                                f"Content-Length: {len(challenge_resp)}\r\n"
                                f"Connection: close\r\n"
                                f"\r\n"
                                f"{challenge_resp}"
                            )
                            client.sendall(http_resp.encode())
                            client.close()
                            continue

                    host_header = ''
                    fwd_proto = ''
                    fwd_port = ''
                    for line in request.split('\r\n'):
                        low = line.lower()
                        if low.startswith('host:'):
                            host_value = line.split(':', 1)[1].strip()
                            if ':' in host_value:
                                host_header = host_value.rsplit(':', 1)[0]
                            else:
                                host_header = host_value
                        elif low.startswith('x-forwarded-proto:'):
                            fwd_proto = line.split(':', 1)[1].strip().lower()
                        elif low.startswith('x-forwarded-port:'):
                            fwd_port = line.split(':', 1)[1].strip()

                    # behind reverse proxy with SSL termination? skip redirect (#125)
                    from pegaprox.utils.audit import _is_trusted_proxy
                    if fwd_proto == 'https' and _is_trusted_proxy(addr[0]):
                        continue

                    # NS Jul 2026 (CodeAnt http-response-splitting) — host_header is untrusted;
                    # strip CR/LF + reject non-hostname chars before it can reach the Location header.
                    import re as _re
                    redirect_host = (host_header or 'localhost').split('/')[0].strip()
                    if not _re.match(r'^[A-Za-z0-9._\-\[\]:]+$', redirect_host):
                        redirect_host = 'localhost'
                    if domain:
                        if ':' in domain and not domain.startswith('['):
                            redirect_host = domain.rsplit(':', 1)[0]
                        else:
                            redirect_host = domain

                    port = int(fwd_port) if fwd_port else https_port
                    if port == 443:
                        redirect_url = f'https://{redirect_host}{path}'
                    else:
                        redirect_url = f'https://{redirect_host}:{port}{path}'

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


# #777 (Frisch12) — the gevent pywsgi request pool holds one greenlet per CONNECTION, and an idle
# keep-alive (or a client that finished the TLS handshake then went silent) parks in
# read_requestline forever, pinning its pool slot; once the pool fills, gevent.baseserver stops
# accepting and the whole instance goes unreachable while the process sits idle. This mixin bounds
# ONLY the inter-request idle read — a request that is actually being served (headers/body, SSE
# streams, uploads, websocket upgrades) is never touched. PEGAPROX_KEEPALIVE_TIMEOUT=0 restores the
# old unbounded behaviour.
_KEEPALIVE_IDLE_TIMEOUT = float(os.environ.get('PEGAPROX_KEEPALIVE_TIMEOUT', '75'))
# MK Sep 2026 - how long a connection may take to finish saying hello. The keepalive
# timeout above covers the wait for the NEXT request line on an idle connection; these two
# cover the two phases before that where a client can simply stop and hold a pool slot
# forever: the TLS handshake, and the headers after the request line. Generous on purpose -
# a phone on a bad train connection still completes both inside a second - but finite,
# because `workers` slots held open is the whole server.
_HANDSHAKE_TIMEOUT = float(os.environ.get('PEGAPROX_HANDSHAKE_TIMEOUT', '30'))
_HEADER_TIMEOUT = float(os.environ.get('PEGAPROX_HEADER_TIMEOUT', '30'))


class _IdleTimeoutMixin:
    """Bound the idle wait for the next request line, and the header read after it.

    Compose ahead of a gevent pywsgi handler class in the MRO so `super().read_requestline()`
    reaches the real handler.

    MK Sep 2026 - read_requestline was the only bounded phase, so `GET / HTTP/1.1` followed by
    headers dribbled one byte at a time held a slot indefinitely: the request line arrived
    promptly, and everything after it was unbounded. Note this bounds the HEADERS only - the
    body is read later, by the application, and a WebSocket upgrade completes its headers in
    one packet like any other request, so a live console is unaffected.
    """
    _idle_timeout = _KEEPALIVE_IDLE_TIMEOUT
    _header_timeout = _HEADER_TIMEOUT

    def read_request(self, raw_requestline):
        to = self._header_timeout
        if not to or to <= 0:
            return super().read_request(raw_requestline)
        import gevent
        t = gevent.Timeout(to)
        t.start()
        try:
            return super().read_request(raw_requestline)
        except gevent.Timeout as ex:
            if ex is t:
                # pywsgi turns a falsy return into a clean 400 and closes the connection
                return False
            raise
        finally:
            t.close()

    def read_requestline(self):
        to = self._idle_timeout
        if not to or to <= 0:
            return super().read_requestline()          # disabled → old unbounded behaviour
        import gevent
        t = gevent.Timeout(to)
        t.start()
        try:
            return super().read_requestline()
        except gevent.Timeout as ex:
            if ex is t:
                return b''    # idle → empty requestline; gevent closes the conn, slot returns
            raise
        finally:
            t.close()


def _no_delay(sock):
    """TCP_NODELAY on an accepted connection.

    MK Oct 2026 (#625) - pywsgi sends the head of a response and its body in two writes.
    With Nagle on, the body waits for the client to ack the head, and a client with
    nothing to send acks 40 ms late: every answer on a kept-alive connection took 40 ms
    more than the network did (a renewal of the HA leader on a LAN: 43 ms instead of 1.5).
    """
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass


def _should_bypass_gevent_upgrade(app, environ):
    """Is this request one that flask-sock will handshake itself?

    geventwebsocket upgrades every request carrying `Upgrade: websocket` at the
    WSGI layer, before Flask routes anything. Our three `@sock.route` endpoints
    are served by simple_websocket, which performs its own handshake once it is
    reached, so the client got two 101 responses, read the second as a frame and
    closed with 1002 (#945.3).

    Decided from the URL map instead of by matching path suffixes: flask-sock
    registers its rules with websocket=True, so this keeps working when a route
    is added or renamed. Anything unroutable, or a werkzeug without websocket
    routing, answers False and leaves the previous behaviour alone.
    MK Sep 2026
    """
    env = environ or {}
    # only an upgrade can be double-upgraded, so ordinary traffic never reaches
    # the routing lookup below
    if 'websocket' not in str(env.get('HTTP_UPGRADE', '')).lower():
        return False
    try:
        adapter = app.url_map.bind('localhost')
        rule = adapter.match(env.get('PATH_INFO', '/'),
                             method=env.get('REQUEST_METHOD', 'GET'),
                             websocket=True, return_rule=True)[0]
        return str(rule.endpoint).startswith('__flask_sock')
    except Exception:
        return False


def _start_gevent_server(app, bind_host, port, ssl_context, domain, workers, http_redirect_port=-1):
    """Start production server with Gevent."""
    from gevent.pywsgi import WSGIServer

    print(f"Starting PegaProx with Gevent WSGIServer ({workers} greenlets)", flush=True)
    print("Mode: Production (async I/O optimized)", flush=True)

    # #945.5 - simple-websocket writes frames with a bare send(), which is allowed
    # to write only part of one. Has to happen before the first websocket is served.
    try:
        from pegaprox.utils.ws_sendall import apply_sendall_patch
        apply_sendall_patch()
    except Exception as _e:
        logging.warning(f"[ws-patch] could not make simple-websocket write whole frames: {_e}")

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
            # MK Sep 2026 (#945.3) - geventwebsocket upgrades EVERY request that
            # carries `Upgrade: websocket`, at the WSGI layer, before Flask routes
            # anything. Three of our routes are flask-sock (`@sock.route`), and
            # simple_websocket.Server performs its own handshake once it is reached.
            # The client therefore received two 101 responses back to back, parsed
            # the second one as a frame, and closed with 1002 Protocol Error. Hand
            # those paths to the plain WSGI handler so exactly one handshake happens.
            #
            # Decided from the URL map rather than by matching path suffixes: a rule
            # registered by flask-sock carries websocket=True, so this stays correct
            # when a route is added or renamed.
            def run_application(self):
                # `app` is the Flask app from the enclosing _start_gevent_server;
                # self.application may be a WSGI wrapper without a url_map
                if _should_bypass_gevent_upgrade(app, self.environ):
                    from gevent.pywsgi import WSGIHandler as _PlainWSGIHandler
                    return _PlainWSGIHandler.run_application(self)
                return super().run_application()

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

            def format_request(self):
                # the access line carries the whole query string, and a token can
                # only travel there for some callers (an older auto-install ISO)
                from pegaprox.utils.sanitization import redact_request_line
                return redact_request_line(super().format_request())
    else:
        QuietWebSocketHandler = None

    # Custom error handler to suppress SSL errors (from bots/scanners/disconnects)
    class QuietWSGIServer(WSGIServer):
        def wrap_socket_and_handle(self, client_socket, address):
            """Override to catch SSL errors and the shutdown GreenletExit during handshake.

            MK Sep 2026 - and to put a clock on the handshake. This method already runs
            inside the spawned greenlet, so a TCP connection that opens and then never
            completes its TLS handshake holds a pool slot for as long as it likes; `workers`
            of those and the server answers nobody, no login required. A real handshake is
            a couple of round trips.
            """
            # A socket timeout, not a gevent.Timeout around the call: the handshake does
            # not necessarily happen inside wrap_socket(). With an stdlib SSLContext it can
            # be deferred to the first read, which lands in the handler - outside any timer
            # we start here. A timeout on the socket travels with it and bounds that read
            # too. handle() clears it the moment the connection is up, so keep-alive and
            # long-lived console sockets are untouched.
            if _HANDSHAKE_TIMEOUT > 0:
                try:
                    client_socket.settimeout(_HANDSHAKE_TIMEOUT)
                except Exception:
                    pass
            _no_delay(client_socket)
            try:
                return super().wrap_socket_and_handle(client_socket, address)
            except (socket.timeout, OSError) as e:
                if isinstance(e, socket.timeout) or 'timed out' in str(e).lower():
                    try:
                        client_socket.close()
                    except Exception:
                        pass
                    return
                raise
            except GreenletExit:
                # gevent cancels connection greenlets on stop(); expected at exit, and it
                # is a BaseException so the handler below would never see it. Its siblings
                # (KeyboardInterrupt, SystemExit, GeneratorExit) are deliberately not caught.
                return
            except Exception as e:
                if 'ssl' in str(type(e).__name__).lower() or 'ssl' in str(e).lower():
                    return
                raise

        def handle(self, sock, address):
            """The handshake is done by the time we get here, so lift its deadline.

            Everything after this point has its own bounds: _IdleTimeoutMixin for the
            request line and the headers, and the application for the body. A console
            WebSocket lives here for hours and must not inherit a 30s socket timeout.
            """
            try:
                sock.settimeout(None)
            except Exception:
                pass
            return super().handle(sock, address)

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
    # MK: Claude helped with the TLS detection logic - checking for 0x16/0x**** bytes
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
                # #777 — bound the pre-request wait: a client that opens the socket but never
                # sends a byte would otherwise park here holding a pool slot until TCP gives up.
                # Drop it after the keep-alive idle window (None = disabled = old blocking behaviour).
                import gevent as _gv
                _pk = _KEEPALIVE_IDLE_TIMEOUT if _KEEPALIVE_IDLE_TIMEOUT > 0 else None
                try:
                    with _gv.Timeout(_pk):
                        first_byte = client_socket.recv(1, socket.MSG_PEEK)
                except _gv.Timeout:
                    client_socket.close()
                    return
                if not first_byte:
                    client_socket.close()
                    return
                if first_byte[0] == 0x16 or first_byte[0] == 0x****:
                    return super().wrap_socket_and_handle(client_socket, address)
                else:
                    # NS: #125 - reverse proxy with SSL termination? serve as plain HTTP
                    # only trust forwarded headers from loopback / configured trusted proxies
                    from pegaprox.utils.audit import _is_trusted_proxy
                    if _is_trusted_proxy(address[0]):
                        try:
                            peek = client_socket.recv(8192, socket.MSG_PEEK)
                            if b'x-forwarded-proto' in peek.lower():
                                for hdr in peek.decode('utf-8', errors='ignore').split('\r\n'):
                                    if hdr.lower().startswith('x-forwarded-proto:'):
                                        if hdr.split(':', 1)[1].strip().lower() == 'https':
                                            return self.handle(client_socket, address)
                                        break
                        except Exception:
                            pass
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

                # NS Jul 2026 (CodeAnt http-response-splitting) — the Host header is untrusted;
                # reject non-hostname chars before it can reach the Location header (open-redirect
                # / header injection). A configured _redirect_domain (below) always wins.
                import re as _re
                if not _re.match(r'^[A-Za-z0-9._\-\[\]:]+$', host or ''):
                    host = 'localhost'

                if self._redirect_domain:
                    d = self._redirect_domain
                    if ':' in d and not d.startswith('['):
                        host = d.rsplit(':', 1)[0]
                    else:
                        host = d

                # NS: #125 - respect proxy headers so we don't redirect to internal port
                fwd_proto = ''
                fwd_port = ''
                for line in request.split('\r\n'):
                    lower = line.lower()
                    if lower.startswith('x-forwarded-proto:'):
                        fwd_proto = line.split(':', 1)[1].strip().lower()
                    elif lower.startswith('x-forwarded-port:'):
                        fwd_port = line.split(':', 1)[1].strip()

                if fwd_proto == 'https':
                    # already behind SSL-terminating proxy, don't redirect
                    return

                port = int(fwd_port) if fwd_port else self.server_port
                if port == 443:
                    redirect_url = f'https://{host}{path}'
                else:
                    redirect_url = f'https://{host}:{port}{path}'

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
    # MK 2026-05-31 — actually wire `workers` into the request-handler pool.
    # gevent.pywsgi.WSGIServer defaults to `spawn=None` which spawns an
    # unlimited greenlet per request. PEGAPROX_WORKERS was a startup-log
    # label only — never enforced. Now caps the request-handling pool at
    # `workers`; per-request fanouts (storage scan, PBS scan, SSH calls)
    # still spawn inside their own request handler.
    from gevent.pool import Pool as _RequestPool

    # #777 — compose the idle-read timeout (module-scope _IdleTimeoutMixin) onto whichever handler
    # is in use, so an idle keep-alive hands its request-pool slot back instead of pinning it.
    from gevent.pywsgi import WSGIHandler as _BaseWSGIHandler
    if use_websocket_handler and QuietWebSocketHandler:
        class _IdleTimeoutHandler(_IdleTimeoutMixin, QuietWebSocketHandler):
            pass
    else:
        class _IdleTimeoutHandler(_IdleTimeoutMixin, _BaseWSGIHandler):
            pass

    server_kwargs = {'log': None, 'spawn': _RequestPool(workers), 'handler_class': _IdleTimeoutHandler}

    is_ipv6_bind = ':' in bind_host

    if ssl_context:
        print(f"HTTPS on https://{bind_host}:{port}", flush=True)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(ssl_context[0], ssl_context[1])
        # NS: http_redirect_port == -1 disables ALL http→https redirect (#125)
        # including the dual-protocol detection on the main port
        if http_redirect_port < 0:
            http_server = QuietWSGIServer(
                _create_listener(bind_host, port), app,
                ssl_context=ssl_ctx,
                **server_kwargs
            )
        else:
            http_server = DualProtocolWSGIServer(
                _create_listener(bind_host, port), app,
                ssl_context=ssl_ctx,
                redirect_domain=domain,
                **server_kwargs
            )
    else:
        print(f"HTTP on http://{bind_host}:{port}", flush=True)
        print("WARNING: Running without HTTPS - noVNC console may not work!", flush=True)
        http_server = QuietWSGIServer(_create_listener(bind_host, port), app, **server_kwargs)

    # Start VNC/SSH WebSocket servers. The SSH one hands back its subprocess so the
    # shutdown path can stop it; the VNC server is a daemon thread and needs no handle.
    ssh_ws_proc = _start_console_servers(bind_host, port, ssl_context)

    # Handle graceful shutdown (#7**** / #784)
    def signal_handler(signum, frame):
        print("\nShutting down gracefully...")
        # terminate() sends SIGTERM and returns immediately, so it is safe from the hub's
        # signal callback. The SSH WebSocket server is a separate process sitting on an
        # endless asyncio Future — nothing else ever stops it, so it survived us and got
        # reparented to init.
        if ssh_ws_proc is not None and ssh_ws_proc.poll() is None:
            try:
                ssh_ws_proc.terminate()
            except Exception:
                pass
        # gevent runs signal handlers inside the hub greenlet, and http_server.stop()
        # blocks on pool.join() — illegal there, which is the BlockingSwitchOutError that
        # made a systemd stop exit 1. Defer it to its own greenlet and bound the join so a
        # long-lived SSE or WebSocket connection cannot hold shutdown open. serve_forever()
        # returns once stop() sets the stop event, so there is no sys.exit() to make here.
        from gevent import spawn
        spawn(lambda: http_server.stop(timeout=10))

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("SSL/WebSocket errors (bots, scanners, disconnects) are suppressed")
    http_server.serve_forever()
