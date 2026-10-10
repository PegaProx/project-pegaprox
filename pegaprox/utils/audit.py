# -*- coding: utf-8 -*-
"""
PegaProx Audit Logging - Layer 3
"""

import os
import json
import time
import logging
from datetime import datetime

from flask import request, has_request_context

from pegaprox.constants import (
    AUDIT_LOG_FILE, AUDIT_LOG_FILE_ENCRYPTED, AUDIT_RETENTION_DAYS,
    MAX_AUDIT_LOG_SIZE,
)
from pegaprox.globals import audit_log
from pegaprox.core.db import get_db
from pegaprox.utils.sanitization import sanitize_log_message

def load_audit_log():
    """Load audit log from SQLite database
    
    SQLite migration
    """
    global audit_log
    
    try:
        db = get_db()
        entries = db.get_audit_log(limit=10000)  # Load recent entries
        audit_log = entries
        logging.info(f"Loaded {len(audit_log)} audit log entries from SQLite")
    except Exception as e:
        logging.error(f"Failed to load audit log from database: {e}")
        # Legacy fallback
        _load_audit_log_legacy()


def _load_audit_log_legacy():
    """Legacy audit log loader"""
    from pegaprox.core.config import get_fernet
    global audit_log
    fernet = get_fernet()
    
    if fernet and os.path.exists(AUDIT_LOG_FILE_ENCRYPTED):
        try:
            with open(AUDIT_LOG_FILE_ENCRYPTED, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            audit_log = json.loads(decrypted_data.decode('utf-8'))
            logging.info(f"Loaded {len(audit_log)} audit entries from legacy encrypted file")
            return
        except:
            pass
    
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, 'r') as f:
                audit_log = json.load(f)
            logging.info(f"Loaded {len(audit_log)} audit entries from legacy JSON file")
            return
        except:
            pass
    
    audit_log = []


def save_audit_log():
    """Save audit log - now handled automatically by database
    
    kept for backwards compat
    Individual entries are saved directly to database via log_audit()
    """
    # In SQLite version, saving is handled per-entry
    # This function is kept for backwards compatibility
    pass


def cleanup_audit_log():
    """Remove audit entries older than retention period.

    NS Apr 2026 — retention is now admin-configurable via settings
    (audit_retention_days). Falls back to AUDIT_RETENTION_DAYS constant
    if setting isn't set yet (fresh install or pre-0.9.8).
    """
    global audit_log

    try:
        db = get_db()
        retention = AUDIT_RETENTION_DAYS
        try:
            v = db.get_server_setting('audit_retention_days', None)
            if v is not None:
                retention = max(30, min(3650, int(v)))
        except Exception:
            pass
        # M5 (scale audit): run the prune OFF the hub. This function was never
        # being called (audit_retention_days went unenforced → audit_log grew
        # unbounded), so the first prune on a months-old install can delete a lot
        # - don't block the gevent event loop on it.
        # MK Oct 2026 - through the db, which leaves a signed checkpoint of what it cut, so
        # the integrity check tells retention from someone deleting rows
        from datetime import datetime as _dt, timedelta as _td
        cutoff = (_dt.now() - _td(days=retention)).isoformat()
        cp = db.prune_audit_log(cutoff)
        logging.info(f"Audit-log retention prune ran (retention={retention}d, cutoff<{cutoff[:10]}, "
                     f"{cp['pruned_rows'] if cp else 0} removed)")
    except Exception as e:
        logging.error(f"Failed to cleanup audit log: {e}")


def checkpoint_audit_log():
    """Sign where this instance's audit chain stands, when it moved since the last time."""
    try:
        return get_db().audit_checkpoint()
    except Exception as e:
        logging.error(f"Failed to checkpoint the audit log: {e}")
        return None

def _via_standby():
    """The standby a write came through while this active runs it for one (#625), ''
    for anything else. The client address is the request's own there: the one the
    standby saw."""
    if not has_request_context():
        return ''
    from pegaprox.core.ha import FORWARD_ENVIRON
    mark = request.environ.get(FORWARD_ENVIRON)
    return str(mark.get('via') or '') if isinstance(mark, dict) else ''


def _audit_cluster_id(cluster):
    """The id of the cluster an entry names, '' when it cannot be told.

    NS Oct 2026 (#1121) - callers pass the display name (a few the id), and any cluster.config
    holder can rename their cluster to another tenant's. The route's own cluster wins when
    the entry names it, else the one cluster that answers to the name or id, else none.
    With no name at all, a cluster route's own cluster is the one the entry is about."""
    from pegaprox.globals import cluster_managers
    route_cid = ''
    if has_request_context():
        route_cid = (request.view_args or {}).get('cluster_id') or ''
    if not cluster:
        return route_cid if route_cid in cluster_managers else ''
    if not isinstance(cluster, str):
        return ''

    def _answers(cid):
        return cluster in (cid, getattr(getattr(cluster_managers.get(cid), 'config', None), 'name', None))

    if route_cid in cluster_managers and _answers(route_cid):
        return route_cid
    hits = [cid for cid in list(cluster_managers) if _answers(cid)]
    return hits[0] if len(hits) == 1 else ''


def log_audit(user: str, action: str, details: str = None, ip_address: str = None, cluster: str = None,
              cluster_id: str = None):
    """Add an entry to the audit log

    writes to db now. cluster is the name shown with the entry, cluster_id the cluster it
    belongs to; left out, it is worked out from the name (_audit_cluster_id).
    """
    global audit_log

    if cluster_id is None:
        try:
            cluster_id = _audit_cluster_id(cluster)
        except Exception:
            cluster_id = ''

    via = _via_standby()
    if via:
        details = f'{details} (via standby {via})' if details else f'via standby {via}'

    entry = {
        'timestamp': datetime.now().isoformat(),
        'user': user,
        'action': action,
        'details': details,
        'ip_address': ip_address or get_client_ip(),
        'cluster': cluster,  # Which cluster this action was performed on
        'cluster_id': cluster_id,
    }
    
    # Add to in-memory list (for backwards compatibility)
    audit_log.insert(0, entry)
    if len(audit_log) > 10000:
        audit_log = audit_log[:10000]
    
    # Save to database
    try:
        db = get_db()
        db.add_audit_entry(
            user=user,
            action=action,
            details=f"{details}" + (f" [{cluster}]" if cluster else ""),
            ip=ip_address or get_client_ip(),
            cluster=cluster or '',
            cluster_id=cluster_id or '',
        )
    except Exception as e:
        logging.error(f"Failed to save audit entry to database: {e}")
    
    # MK May 2026 - CWE-117. user / action / details / cluster all flow through
    # API inputs; strip CR/LF before they hit the text logger so an attacker can't
    # forge a fake follow-up audit line. DB row above keeps the raw value.
    safe_user = sanitize_log_message(user)
    safe_action = sanitize_log_message(action)
    safe_details = sanitize_log_message(details)
    safe_cluster = sanitize_log_message(cluster) if cluster else ""
    cluster_info = f" [{safe_cluster}]" if safe_cluster else ""
    logging.info(f"Audit: {safe_user} - {safe_action}{cluster_info} - {safe_details}")

def _is_loopback(addr):
    """Check if address is loopback (trusted proxy)
    MK Feb 2026 - dual-stack sockets report IPv4 loopback as ::ffff:127.0.0.1
    """
    if addr and addr.startswith('::ffff:'):
        addr = addr[7:]
    return addr in ('127.0.0.1', '::1', '127.0.0.0')

# NS Mar 2026 - trusted proxy list for non-loopback reverse proxies (nginx on different host)
# loaded once at startup from DB, updated via settings API
_trusted_proxies = set()  # IPs and/or CIDR networks

def load_trusted_proxies(proxy_str=''):
    """Parse comma-separated IPs/CIDRs into the trusted set."""
    global _trusted_proxies
    import ipaddress
    result = set()
    if not proxy_str:
        _trusted_proxies = result
        return
    for entry in proxy_str.split(','):
        entry = entry.strip()
        if not entry: continue
        try:
            if '/' in entry:
                result.add(ipaddress.ip_network(entry, strict=False))
            else:
                result.add(ipaddress.ip_address(entry))
        except ValueError:
            logging.warning(f"[Proxy] invalid trusted proxy entry: {entry}")
    _trusted_proxies = result

def _is_trusted_proxy(addr):
    """MK: check if addr is loopback or in trusted_proxies list"""
    if _is_loopback(addr):
        return True
    if not _trusted_proxies:
        return False
    import ipaddress
    try:
        # strip ::ffff: prefix for comparison
        clean = addr[7:] if addr and addr.startswith('::ffff:') else addr
        ip = ipaddress.ip_address(clean)
        for trusted in _trusted_proxies:
            if isinstance(trusted, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if ip in trusted: return True
            elif ip == trusted:
                return True
    except ValueError:
        pass
    return False

def _canonical_ip(addr):
    """Normalize an IP so IPv4-mapped IPv6 (::ffff:1.2.3.4) and bare IPv4 (1.2.3.4)
    key to the same value. Without this, lockout/rate-limit buckets split across
    the two forms — pentest Apr 2026 showed a source could double its rate budget
    by toggling XFF presence. NS."""
    if not addr:
        return addr
    if addr.startswith('::ffff:'):
        return addr[7:]
    return addr

def get_client_ip():
    """Get client IP address from request
    NS Feb 2026 - only trust X-Forwarded-For from trusted sources
    NS 2026-04-24 - canonicalize to close the ::ffff:/IPv4 lockout-bucket split
    """
    if not has_request_context():
        return 'system'
    return client_ip_from(request.remote_addr, request.headers.get)


def client_ip_from(remote_addr, header):
    """get_client_ip() for a request read straight from its WSGI environ: `remote_addr`
    the peer address, `header(name)` the value of a request header or None. MK Oct 2026
    (#625) - the HA lease routes answer before Flask (app._LeaseFastPath) and go by the
    same address the IP lists see."""
    # trust proxy headers from loopback + configured trusted proxies
    if _is_trusted_proxy(remote_addr):
        xff = header('X-Forwarded-For')
        if xff:
            # sec (audit): the LEFTMOST entry is whatever the client sent — a proxy APPENDS the
            # peer it saw, so `X-Forwarded-For: 1.2.3.4` from the client arrives as
            # "1.2.3.4, <real ip>". Taking [0] let any user behind the proxy choose their own
            # source address, which is the key for the login-lockout buckets, the auth-action
            # rate limiter, the IP allow/deny list and every audit line.
            # Walk from the RIGHT instead and take the first hop we did not put there
            # ourselves. A replacing proxy (single entry) and an appending one both land on
            # the real client.
            _hops = [p.strip() for p in xff.split(',') if p.strip()]
            for _cand in reversed(_hops):
                if not _is_trusted_proxy(_cand):
                    return _canonical_ip(_cand)
            # every hop is one of our own proxies — the peer is as close as we get
            return _canonical_ip(remote_addr)
        xri = header('X-Real-IP')
        if xri:
            return _canonical_ip(xri.strip())
    return _canonical_ip(remote_addr)

# Global users store (loaded at startup)
users_db = {}

