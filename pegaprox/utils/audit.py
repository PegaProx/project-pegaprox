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
        deleted = db.cleanup_audit_log(days=retention)
        if deleted > 0:
            logging.info(f"Cleaned up {deleted} old audit log entries (retention={retention}d)")
    except Exception as e:
        logging.error(f"Failed to cleanup audit log: {e}")

def log_audit(user: str, action: str, details: str = None, ip_address: str = None, cluster: str = None):
    """Add an entry to the audit log
    
    writes to db now
    """
    global audit_log
    
    entry = {
        'timestamp': datetime.now().isoformat(),
        'user': user,
        'action': action,
        'details': details,
        'ip_address': ip_address or get_client_ip(),
        'cluster': cluster  # Which cluster this action was performed on
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
        )
    except Exception as e:
        logging.error(f"Failed to save audit entry to database: {e}")
    
    cluster_info = f" [{cluster}]" if cluster else ""
    logging.info(f"Audit: {user} - {action}{cluster_info} - {details}")

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
    # trust proxy headers from loopback + configured trusted proxies
    if _is_trusted_proxy(request.remote_addr):
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            return _canonical_ip(xff.split(',')[0].strip())
        xri = request.headers.get('X-Real-IP')
        if xri:
            return _canonical_ip(xri.strip())
    return _canonical_ip(request.remote_addr)

# Global users store (loaded at startup)
users_db = {}

