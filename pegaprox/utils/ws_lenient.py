"""Lenient WebSocket opening handshake.

# What & why
werkzeug (for routing) and simple-websocket (for the handshake) both want the HTTP
`Connection` header of a WS upgrade request to contain the token "upgrade". Browsers
send `Connection: keep-alive, Upgrade` per RFC 6455 §4.2.1, which passes.
Some intermediaries strip the `Upgrade` token and leave only `keep-alive`.

We've seen this happen in two production patterns:

1. **TLS-inspection / EDR proxies** that re-write the Connection header before
   passing the upgrade through.
2. **Proxmox VE 9.1.8-9.1.9 hosts** running PegaProx co-located on the PVE
   node. The PVE-side traffic-handling stack started normalising Connection
   headers in a way that drops the `Upgrade` token. Reported as PegaProx
   GitHub issue #352 by multiple users on different OSes (no AV in common),
   pinpointed by user `eugen-optimus` to PVE 9.1.8-9.1.9 specifically.

# Fix
If the request looks like a valid WS upgrade attempt (has `Upgrade: websocket`
and a Sec-WebSocket-Key) but the `Connection` header is missing the `upgrade`
token, we inject it back before anything reads it. That matches what every
well-known WS server does in practice (mod_proxy_wstunnel, HAProxy, Nginx all
do the equivalent). We log a one-shot warning when we patch a request so support
can correlate.

# What we do NOT do
We do not relax other handshake checks (Sec-WebSocket-Key, version 13, etc.).
Those genuinely matter for the protocol. Only Connection is fragile-by-proxy.

MK Apr 2026 — driven by Issue #352, fix targeted at the actual symptom on PVE
9.1.8-9.1.9 hosts, also helps with the wider middlebox class of issues. It sat in
front of the console servers on port+1/+2 as a `websockets` hook; MK Nov 2026 the
consoles are WSGI routes of the main port, and so is the repair.
"""
import logging

_LEN_NOTIFIED = set()  # remote-addr keys we've already warned for, keep noise low


def repair_upgrade_environ(environ):
    """werkzeug only routes a request to a websocket rule when Connection carries the
    `upgrade` token, and simple-websocket's handshake asks the same, so a stripped token
    sent the VNC console to the plain HTTP route (426) and gave the shell and terminal no
    socket at all. Mutates environ; True when it did."""
    if 'websocket' not in str(environ.get('HTTP_UPGRADE', '')).lower():
        return False
    if not environ.get('HTTP_SEC_WEBSOCKET_KEY'):
        return False
    conn_val = str(environ.get('HTTP_CONNECTION', '') or '')
    tokens = [t.strip().lower() for t in conn_val.split(',') if t.strip()]
    if 'upgrade' in tokens:
        return False
    environ['HTTP_CONNECTION'] = (conn_val + ', Upgrade').strip(', ') if conn_val else 'Upgrade'
    key = environ.get('REMOTE_ADDR') or 'unknown'
    if key not in _LEN_NOTIFIED:
        _LEN_NOTIFIED.add(key)
        if len(_LEN_NOTIFIED) > 256:
            _LEN_NOTIFIED.clear()
        logging.warning(
            f"[WS-Lenient] patched Connection header for {key} "
            f"(was {conn_val!r}, restored 'Upgrade' token). "
            "Likely a proxy/EDR or PVE 9.1.8+ stripping the token."
        )
    return True


class LenientUpgrade:
    """WSGI wrapper around the app that runs repair_upgrade_environ first."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        repair_upgrade_environ(environ)
        return self.wsgi_app(environ, start_response)
