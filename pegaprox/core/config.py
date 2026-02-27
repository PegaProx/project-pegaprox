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
    """Get existing encryption key or create a new one"""
    if not ENCRYPTION_AVAILABLE:
        return None
    
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    
    # Generate new key
    key = Fernet.generate_key()
    
    # Save key with restricted permissions
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    
    # Set file permissions to owner only (Unix)
    try:
        os.chmod(KEY_FILE, 0o600)
    except:
        pass
    
    logging.info("Generated new encryption key")
    return key

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
    """Legacy config loader - used as fallback if database fails"""
    fernet = get_fernet()
    
    # Try encrypted file
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
    
    # Try unencrypted file
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            if config:
                logging.info(f"✓ Loaded {len(config)} clusters from legacy JSON file")
                return config
        except Exception as e:
            logging.error(f"Failed to load legacy config: {e}")
    
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
                fallback_hosts = manager.config.fallback_hosts or []
                if not isinstance(fallback_hosts, list):
                    fallback_hosts = []
                fallback_hosts = [str(h) for h in fallback_hosts if h]
                
                cluster_data = {
                    'name': manager.config.name,
                    'host': manager.config.host,
                    'user': manager.config.user,
                    'pass': manager.config.pass_,
                    'ssl_verification': manager.config.ssl_verification,
                    'migration_threshold': manager.config.migration_threshold,
                    'check_interval': manager.config.check_interval,
                    'auto_migrate': manager.config.auto_migrate,
                    'balance_containers': getattr(manager.config, 'balance_containers', False),
                    'balance_local_disks': getattr(manager.config, 'balance_local_disks', False),
                    'dry_run': manager.config.dry_run,
                    'enabled': manager.config.enabled,
                    'ha_enabled': manager.config.ha_enabled,
                    'fallback_hosts': fallback_hosts,
                    'ssh_user': getattr(manager.config, 'ssh_user', ''),
                    'ssh_key': getattr(manager.config, 'ssh_key', ''),
                    'ssh_port': getattr(manager.config, 'ssh_port', 22),
                    'ha_settings': getattr(manager.config, 'ha_settings', {}),
                    'excluded_nodes': getattr(manager.config, 'excluded_nodes', []),
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



