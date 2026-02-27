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
    """Remove audit entries older than retention period
    
    uses db.delete now
    """
    global audit_log
    
    try:
        db = get_db()
        deleted = db.cleanup_audit_log(days=AUDIT_RETENTION_DAYS)
        if deleted > 0:
            logging.info(f"Cleaned up {deleted} old audit log entries")
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
            ip=ip_address or get_client_ip()
        )
    except Exception as e:
        logging.error(f"Failed to save audit entry to database: {e}")
    
    cluster_info = f" [{cluster}]" if cluster else ""
    logging.info(f"Audit: {user} - {action}{cluster_info} - {details}")

def get_client_ip():
    """Get client IP address from request"""
    # NS Feb 2026 - background threads (scheduler, metrics) have no Flask context
    if not has_request_context():
        return 'system'
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

# Global users store (loaded at startup)
users_db = {}

