"""Lenient WebSocket opening-handshake helper for `websockets.serve`.

# What & why
The Python `websockets` library (≥11) strict-validates the HTTP `Connection`
header on a WS upgrade request: it must contain the token "upgrade". Browsers
send `Connection: keep-alive, Upgrade` per RFC 6455 §4.2.1, which passes.
Some intermediaries strip the `Upgrade` token and leave only `keep-alive`,
which makes `websockets` raise `InvalidUpgrade("Connection", "keep-alive")` —
surfaced to the customer as a 426 page with body "invalid Connection header:
keep-alive".

We've seen this happen in two production patterns:

1. **TLS-inspection / EDR proxies** that re-write the Connection header before
   passing the upgrade through.
2. **Proxmox VE 9.1.8-9.1.9 hosts** running PegaProx co-located on the PVE
   node. The PVE-side traffic-handling stack started normalising Connection
   headers in a way that drops the `Upgrade` token. Reported as PegaProx
   GitHub issue #352 by multiple users on different OSes (no AV in common),
   pinpointed by user `eugen-optimus` to PVE 9.1.8-9.1.9 specifically.

# Fix
We hand the `websockets.serve` call a `process_request` callback that runs
*before* the upgrade is validated. If the request looks like a valid WS
upgrade attempt (has `Upgrade: websocket` and a Sec-WebSocket-Key) but the
`Connection` header is missing the `upgrade` token, we inject it back. That
matches what every well-known WS server does in practice (mod_proxy_wstunnel,
HAProxy, Nginx all do the equivalent). We log a one-shot warning when we
patch a request so support can correlate.

# What we do NOT do
We do not relax other handshake checks (Sec-WebSocket-Key, version 13, etc.).
Those genuinely matter for the protocol. Only Connection is fragile-by-proxy.

MK Apr 2026 — driven by Issue #352, fix targeted at the actual symptom on PVE
9.1.8-9.1.9 hosts, also helps with the wider middlebox class of issues.
"""
import logging

_LEN_NOTIFIED = set()  # remote-addr keys we've already warned for, keep noise low


def lenient_process_request(connection, request):
    """Pre-handshake hook to be passed as `process_request=` to `websockets.serve`.

    Mutates `request.headers` in place if a stripped Connection header is
    detected. Returns None to let the normal handshake validation proceed.
    """
    headers = request.headers
    upgrade_val = ''
    try:
        upgrade_val = headers.get('Upgrade', '') or ''
    except Exception:
        upgrade_val = ''
    if 'websocket' not in upgrade_val.lower():
        # Not a WS upgrade attempt at all — let the lib reject normally.
        return None

    try:
        conn_val = headers.get('Connection', '') or ''
    except Exception:
        conn_val = ''
    tokens = [t.strip().lower() for t in conn_val.split(',') if t.strip()]
    if 'upgrade' in tokens:
        return None  # already correct

    # Patch: replace Connection header with one that contains "Upgrade".
    new_conn = (conn_val + ', Upgrade').strip(', ') if conn_val else 'Upgrade'
    try:
        del headers['Connection']
    except Exception:
        pass
    headers['Connection'] = new_conn

    # One-shot warning per remote so we can diagnose at the customer without
    # spamming the log.
    try:
        peer = connection.remote_address[0] if hasattr(connection, 'remote_address') else None
    except Exception:
        peer = None
    key = peer or 'unknown'
    if key not in _LEN_NOTIFIED:
        _LEN_NOTIFIED.add(key)
        if len(_LEN_NOTIFIED) > 256:
            _LEN_NOTIFIED.clear()
        logging.warning(
            f"[WS-Lenient] patched Connection header for {key} "
            f"(was {conn_val!r}, restored 'Upgrade' token). "
            "Likely a proxy/EDR or PVE 9.1.8+ stripping the token."
        )
    return None
