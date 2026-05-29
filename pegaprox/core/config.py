# -*- coding: utf-8 -*-
"""
PegaProx Config Management - Layer 3
Encryption key management and config load/save.
"""

import os
import json
import logging
import base64
from pathlib import Path

from pegaprox.constants import CONFIG_DIR, KEY_FILE, CONFIG_FILE, CONFIG_FILE_ENCRYPTED
from pegaprox.core.db import get_db, ENCRYPTION_AVAILABLE
from pegaprox.globals import cluster_managers

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    pass

def get_or_create_encryption_key():
    """Get the master key — now resolved by `pegaprox.core.keystore`.

    Kept as a back-compat shim so older imports (audit.py, plugins) keep
    working.  The actual resolution logic moved to keystore.load_master_key()
    which supports systemd LoadCredentialEncrypted, env vars, /etc/pegaprox/,
    user-config and the legacy CONFIG_DIR location (in priority order).

    MK May 2026 (Stufe 1+2 of the security-review response).
    """
    if not ENCRYPTION_AVAILABLE:
        return None
    try:
        from pegaprox.core.keystore import load_master_key
        return load_master_key().key_b64
    except Exception as e:
        logging.error(f"[CONFIG] keystore.load_master_key() failed: {e}")
        return None

def get_fernet():
    """Get Fernet encryption instance"""
    if not ENCRYPTION_AVAILABLE:
        return None

    key = get_or_create_encryption_key()
    if key:
        return Fernet(key)
    return None

def load_config():
    """Load configuration from SQLite database
    
    refactored to use SQLite
    Automatically migrates existing JSON/encrypted files on first run
    """
    logging.info("=== Loading config from SQLite ===")
    
    try:
        db = get_db()
        config = db.get_all_clusters()
        
        if config:
            logging.info(f"✓ Loaded {len(config)} clusters from SQLite: {list(config.keys())}")
            return config
        else:
            logging.info("No clusters in database yet")
            return {}
    except Exception as e:
        logging.error(f"Failed to load config from database: {e}")
        import traceback
        logging.error(traceback.format_exc())
        
        # Emergency fallback to legacy files
        logging.info("Attempting legacy fallback...")
        return _load_config_legacy()


def _load_config_legacy():
    """Legacy config loader - used as fallback if database fails

    NS May 2026 - plain-JSON CONFIG_FILE (clusters.json) fallback dropped. The
    only legacy path still trusted here is the Fernet-encrypted .enc file (which
    was already encrypted-at-rest). A plain-text spill would defeat the whole
    SQLCipher migration done in v0.9.10. If both DB load and the .enc fallback
    fail, return empty and let the caller deal with it — operator has to fix the
    DB, not bring back a JSON file.
    """
    fernet = get_fernet()

    # Encrypted-only legacy fallback
    if fernet and os.path.exists(CONFIG_FILE_ENCRYPTED):
        try:
            with open(CONFIG_FILE_ENCRYPTED, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            config = json.loads(decrypted_data.decode('utf-8'))
            if config:
                logging.info(f"✓ Loaded {len(config)} clusters from legacy encrypted file")
                return config
        except Exception as e:
            logging.error(f"Failed to load legacy encrypted config: {e}")

    return {}


def save_config():
    """Save configuration to SQLite database
    
    SQLite instead of JSON now
    """
    if not cluster_managers:
        logging.warning("save_config called with no clusters - skipping")
        return False

    try:
        db = get_db()

        for cluster_id, manager in cluster_managers.items():
            try:
                # Sanitize fallback_hosts
                fallback_hosts = getattr(manager.config, 'fallback_hosts', []) or []
                if not isinstance(fallback_hosts, list):
                    fallback_hosts = []
                fallback_hosts = [str(h) for h in fallback_hosts if h]

                cluster_data = {
                    'name': manager.config.name,
                    'host': manager.config.host,
                    'user': manager.config.user,
                    'pass': manager.config.pass_,
                    'ssl_verification': getattr(manager.config, 'ssl_verification', False),
                    'migration_threshold': getattr(manager.config, 'migration_threshold', 30),
                    'migration_tolerance': getattr(manager.config, 'migration_tolerance', 10),
                    'check_interval': getattr(manager.config, 'check_interval', 300),
                    'auto_migrate': getattr(manager.config, 'auto_migrate', False),
                    'balance_containers': getattr(manager.config, 'balance_containers', False),
                    'balance_local_disks': getattr(manager.config, 'balance_local_disks', False),
                    'dry_run': getattr(manager.config, 'dry_run', False),
                    'enabled': getattr(manager.config, 'enabled', True),
                    'ha_enabled': getattr(manager.config, 'ha_enabled', False),
                    'fallback_hosts': fallback_hosts,
                    'ssh_user': getattr(manager.config, 'ssh_user', ''),
                    'ssh_key': getattr(manager.config, 'ssh_key', ''),
                    'ssh_port': getattr(manager.config, 'ssh_port', 22),
                    'ha_settings': getattr(manager.config, 'ha_settings', {}),
                    'excluded_nodes': getattr(manager.config, 'excluded_nodes', []),
                    'api_token_user': getattr(manager.config, 'api_token_user', ''),
                    'api_token_secret': getattr(manager.config, 'api_token_secret', ''),
                    'cluster_type': getattr(manager, 'cluster_type', 'proxmox'),
                    'vnc_tunnel': bool(getattr(manager.config, 'vnc_tunnel', False)),  # MK Apr 2026
                    # NS May 2026 (#364) — load-balancer settings used to be set
                    # on the in-memory config object but never made it into the
                    # save dict, so they reverted on the next reload.
                    'predictive_balancing': bool(getattr(manager.config, 'predictive_balancing', False)),
                    'predictive_threshold': float(getattr(manager.config, 'predictive_threshold', 0.0) or 0.0),
                    'balance_cpu_weight': float(getattr(manager.config, 'balance_cpu_weight', 1.0) or 1.0),
                    'balance_mem_weight': float(getattr(manager.config, 'balance_mem_weight', 1.0) or 1.0),
                    'balance_io_weight': float(getattr(manager.config, 'balance_io_weight', 1.0) or 1.0),
                    'cpu_baseline': getattr(manager.config, 'cpu_baseline', '') or '',
                    'backup_sla_max_age_hours': int(getattr(manager.config, 'backup_sla_max_age_hours', 0) or 0),
                    # MK May 2026 — Proxmox API port override (default 8006). Direct-TLS only.
                    'api_port': int(getattr(manager.config, 'api_port', 8006) or 8006),
                }

                db.save_cluster(cluster_id, cluster_data)
            except Exception as e:
                logging.error(f"Error saving cluster {cluster_id}: {e}")
                continue
        
        logging.debug(f"Saved {len(cluster_managers)} clusters to SQLite")
        return True
        
    except Exception as e:
        logging.error(f"Failed to save config to database: {e}")
        return False


# old version, keep for reference
# def save_config_v1(config):
#     with open(CONFIG_FILE, 'w') as f:
#         json.dump(config, f, indent=2)



