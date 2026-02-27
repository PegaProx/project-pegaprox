# -*- coding: utf-8 -*-
"""
PegaProx Database - Layer 2
SQLite database wrapper with encryption support.
"""
# MK: the db stuff was the worst part of the monolith, everything was just inline sql

import os
import sys
import json
import time
import logging
import threading
import hashlib
import hmac
import base64
import uuid
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

from pegaprox.constants import (
    DATABASE_FILE, CONFIG_DIR, KEY_FILE, CONFIG_FILE, CONFIG_FILE_ENCRYPTED,
    USERS_FILE_ENCRYPTED, AUDIT_LOG_FILE, AUDIT_LOG_FILE_ENCRYPTED,
    SESSIONS_FILE, SESSIONS_FILE_ENCRYPTED, ALERTS_CONFIG_FILE,
    SCHEDULED_TASKS_FILE, VM_TAGS_FILE, AFFINITY_RULES_FILE,
    MIGRATION_HISTORY_FILE, SERVER_SETTINGS_FILE, CUSTOM_ROLES_FILE,
    ESXI_CONFIG_FILE, STORAGE_CLUSTERS_FILE,
)

# Fallback tenant ID for existing users (mirrors pegaprox.utils.rbac.DEFAULT_TENANT_ID)
# Defined here to avoid circular import: rbac imports from db
DEFAULT_TENANT_ID = 'default'

# Encryption imports
ENCRYPTION_AVAILABLE = False
LEGACY_ENCRYPTION = False
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    ENCRYPTION_AVAILABLE = True
    LEGACY_ENCRYPTION = True
except ImportError:
    pass

class PegaProxDB:
    """
    SQLite database wrapper - MK
    
    switched from json files because they kept corrupting when multiple
    requests came in. wasted a whole weekend on that shit lol
    
    sensitive stuff (passwords etc) is encrypted, rest is plain text
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        # singleton - only one db connection
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.db_path = DATABASE_FILE
        self.fernet = None  # old encryption, keep for migration
        self.aesgcm = None  # new aes256
        self.aes_key = None  # raw key for HMAC signing
        self._conn = None
        self._local = threading.local()
        
        self._init_encryption()
        self._init_db()
        self._migrate_from_legacy()
        
        self._initialized = True
        logging.info(f"DB initialized: {self.db_path}")
    
    def _init_encryption(self):
        """setup encryption keys"""
        # MK: upgraded to aes256 in jan 2026, old fernet stuff still works
        if not ENCRYPTION_AVAILABLE:
            logging.warning("no encryption available!")
            return
        
        # AES-256 key file
        aes_key_file = os.path.join(CONFIG_DIR, '.pegaprox_aes256.key')
        
        # Load or generate AES-256 key
        if os.path.exists(aes_key_file):
            with open(aes_key_file, 'rb') as f:
                aes_key = f.read()
            if len(aes_key) != 32:
                logging.warning("Invalid AES key length, regenerating...")
                aes_key = os.urandom(32)  # 256 bits
                with open(aes_key_file, 'wb') as f:
                    f.write(aes_key)
        else:
            # Generate new 256-bit key
            aes_key = os.urandom(32)
            with open(aes_key_file, 'wb') as f:
                f.write(aes_key)
            try:
                os.chmod(aes_key_file, 0o600)
            except:
                pass
            logging.info("Generated new AES-256-GCM encryption key (Military Grade)")
        
        self.aesgcm = AESGCM(aes_key)
        self.aes_key = aes_key  # Store raw key for HMAC signing
        
        # Load legacy Fernet key for backwards compatibility
        if os.path.exists(KEY_FILE):
            try:
                with open(KEY_FILE, 'rb') as f:
                    fernet_key = f.read()
                self.fernet = Fernet(fernet_key)
                logging.debug("Loaded legacy Fernet key for migration support")
            except Exception as e:
                logging.warning(f"Could not load legacy Fernet key: {e}")
        else:
            # Generate Fernet key for potential fallback
            fernet_key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as f:
                f.write(fernet_key)
            try:
                os.chmod(KEY_FILE, 0o600)
            except:
                pass
            self.fernet = Fernet(fernet_key)
            logging.info("Generated legacy Fernet key (for compatibility)")
    
    def _get_connection(self):
        """Get thread-local database connection
        
        NS: Using thread-local storage because SQLite connections
        shouldn't be shared across threads. Each thread gets its own.
        """
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,  # We handle thread safety ourselves
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            # Enable foreign keys
            self._local.conn.execute("PRAGMA foreign_keys = ON")
            # WAL mode for better concurrency (multiple readers, one writer)
            self._local.conn.execute("PRAGMA journal_mode = WAL")
        return self._local.conn
    
    @property
    def conn(self):
        return self._get_connection()
    
    def _init_db(self):
        """Initialize database schema
        
        NS: Also sets restrictive file permissions (0600) on the database file.
        This prevents other users on the system from reading the DB.
        """
        conn = self.conn
        cursor = conn.cursor()
        
        # NS: Set restrictive permissions on DB file - only owner can read/write
        # This is critical security - DB contains encrypted secrets and session data
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
                logging.debug(f"Set database file permissions to 0600")
        except Exception as e:
            logging.warning(f"Could not set database file permissions: {e}")
        
        # Clusters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clusters (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                user TEXT NOT NULL,
                pass_encrypted TEXT NOT NULL,
                ssl_verification INTEGER DEFAULT 1,
                migration_threshold INTEGER DEFAULT 30,
                check_interval INTEGER DEFAULT 300,
                auto_migrate INTEGER DEFAULT 0,
                balance_containers INTEGER DEFAULT 0,
                balance_local_disks INTEGER DEFAULT 0,
                dry_run INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1,
                ha_enabled INTEGER DEFAULT 0,
                fallback_hosts TEXT DEFAULT '[]',
                ssh_user TEXT DEFAULT '',
                ssh_key_encrypted TEXT DEFAULT '',
                ssh_port INTEGER DEFAULT 22,
                ha_settings TEXT DEFAULT '{}',
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                permissions TEXT DEFAULT '[]',
                tenant TEXT,
                created_at TEXT,
                last_login TEXT,
                password_expiry TEXT,
                totp_secret_encrypted TEXT,
                totp_pending_secret_encrypted TEXT,
                totp_enabled INTEGER DEFAULT 0,
                force_password_change INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                theme TEXT DEFAULT '',
                language TEXT DEFAULT '',
                ui_layout TEXT DEFAULT 'modern',
                taskbar_auto_expand INTEGER DEFAULT 1,
                auth_source TEXT DEFAULT 'local',
                display_name TEXT DEFAULT '',
                email TEXT DEFAULT '',
                ldap_dn TEXT DEFAULT '',
                last_ldap_sync TEXT DEFAULT '',
                tenant_permissions TEXT DEFAULT '{}',
                denied_permissions TEXT DEFAULT '[]',
                oidc_sub TEXT DEFAULT '',
                last_oidc_sync TEXT DEFAULT ''
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT,
                expires_at TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        # Audit log table with HMAC integrity verification
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                hmac_signature TEXT
            )
        ''')
        
        # Create index for audit log queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user)
        ''')
        
        # NS: Task-User mapping table for tracking who initiated tasks
        # This persists across server restarts and is visible to all users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_users (
                upid TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                cluster_id TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Cleanup old task_users entries (older than 24 hours)
        cursor.execute('''
            DELETE FROM task_users 
            WHERE datetime(created_at) < datetime('now', '-24 hours')
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                cluster_id TEXT,
                node TEXT,
                vmid INTEGER,
                type TEXT NOT NULL,
                threshold REAL,
                enabled INTEGER DEFAULT 1,
                notify_methods TEXT DEFAULT '[]',
                cooldown INTEGER DEFAULT 300,
                last_triggered TEXT,
                created_at TEXT
            )
        ''')
        
        # VM ACLs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vm_acls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid TEXT NOT NULL,
                users TEXT DEFAULT '[]',
                permissions TEXT DEFAULT '[]',
                UNIQUE(cluster_id, vmid)
            )
        ''')
        
        # Affinity rules table
        # MK: added enforce column Feb 2026 - was losing this value on every restart lol
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS affinity_rules (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                vms TEXT NOT NULL DEFAULT '[]',
                enabled INTEGER DEFAULT 1,
                enforce INTEGER DEFAULT 0,
                created_at TEXT
            )
        ''')
        
        # Tenants - requested on reddit
        # Someone on Reddit asked for multi-tenancy support, turns out its
        # pretty useful for MSPs managing multiple customers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                clusters TEXT DEFAULT '[]',
                created_at TEXT
            )
        ''')
        
        # Cluster Groups - organize clusters into collapsible groups with tenant assignment
        # NS: Jan 2026 - requested by user for better organization
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cluster_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                color TEXT DEFAULT '#E86F2D',
                tenant_id TEXT,
                sort_order INTEGER DEFAULT 0,
                collapsed INTEGER DEFAULT 0,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        ''')
        
        # Custom roles table - need composite key for name + tenant_id
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_roles (
                name TEXT NOT NULL,
                permissions TEXT NOT NULL DEFAULT '[]',
                description TEXT,
                tenant_id TEXT,
                created_at TEXT,
                PRIMARY KEY (name, tenant_id)
            )
        ''')
        
        # Migration: Recreate table with correct schema if needed
        try:
            cursor.execute("SELECT tenant_id FROM custom_roles LIMIT 1")
        except:
            # Old table without tenant_id - recreate
            cursor.execute("DROP TABLE IF EXISTS custom_roles")
            cursor.execute('''
                CREATE TABLE custom_roles (
                    name TEXT NOT NULL,
                    permissions TEXT NOT NULL DEFAULT '[]',
                    description TEXT,
                    tenant_id TEXT,
                    created_at TEXT,
                    PRIMARY KEY (name, tenant_id)
                )
            ''')
        
        # Scheduled tasks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id TEXT PRIMARY KEY,
                cluster_id TEXT,
                name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                schedule TEXT NOT NULL,
                config TEXT DEFAULT '{}',
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                next_run TEXT,
                created_at TEXT
            )
        ''')
        
        # VM Tags table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vm_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                tag_name TEXT NOT NULL,
                tag_color TEXT,
                UNIQUE(cluster_id, vmid, tag_name)
            )
        ''')
        
        # Balancing excluded VMs table - MK Jan 2026
        # VMs that should not be automatically migrated during load balancing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at TEXT,
                UNIQUE(cluster_id, vmid)
            )
        ''')
        
        # Migration history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS migration_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                vm_name TEXT,
                source_node TEXT NOT NULL,
                target_node TEXT NOT NULL,
                reason TEXT,
                status TEXT,
                duration_seconds REAL,
                timestamp TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_migration_timestamp ON migration_history(timestamp DESC)
        ''')
        
        # Server settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # User favorites table - NS Jan 2026
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                cluster_id TEXT,
                vmid INTEGER,
                vm_type TEXT,
                vm_name TEXT,
                added_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_favorites_user ON user_favorites(username)
        ''')
        
        # Scheduled actions table - NS Jan 2026
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT,
                vmid INTEGER,
                action TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                schedule_time TEXT,
                schedule_days TEXT,
                schedule_date TEXT,
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                created_by TEXT,
                created_at TEXT
            )
        ''')
        
        # Update schedules table - MK Jan 2026
        # For automatic rolling updates
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_schedules (
                cluster_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 0,
                schedule_type TEXT DEFAULT 'recurring',
                day TEXT DEFAULT 'sunday',
                time TEXT DEFAULT '03:00',
                include_reboot INTEGER DEFAULT 1,
                skip_evacuation INTEGER DEFAULT 0,
                skip_up_to_date INTEGER DEFAULT 1,
                evacuation_timeout INTEGER DEFAULT 1800,
                last_run TEXT,
                next_run TEXT,
                created_by TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Metrics history table - NS Jan 2026
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp DESC)
        ''')
        
        # Custom Scripts table - MK Jan 2026
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_scripts (
                id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                type TEXT DEFAULT 'bash',
                content TEXT NOT NULL,
                target_nodes TEXT DEFAULT 'all',
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                last_status TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scripts_cluster ON custom_scripts(cluster_id)
        ''')
        
        # NS: Additional tables for full JSON migration - Jan 2026
        # MK: finally got around to migrating all the random json files to sqlite
        # took way longer than expected but now everything is in one place
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cluster_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                config TEXT DEFAULT '{}',
                enabled INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(cluster_id, alert_type)
            )
        ''')
        
        # LW: ESXi integration was a pain, but people kept asking for it
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS esxi_storages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                username TEXT,
                password_encrypted TEXT,
                datastore TEXT,
                enabled INTEGER DEFAULT 1,
                last_sync TEXT,
                config TEXT DEFAULT '{}'
            )
        ''')
        
        # NS: storage clusters for ceph/gluster/zfs pools shared across nodes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS storage_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                name TEXT NOT NULL,
                storage_type TEXT DEFAULT 'ceph',
                nodes TEXT DEFAULT '[]',
                config TEXT DEFAULT '{}',
                enabled INTEGER DEFAULT 1,
                UNIQUE(cluster_id, name)
            )
        ''')
        
        # MK: Pool Permissions - Jan 2026
        # Store permissions for Proxmox resource pools
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pool_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                permissions TEXT DEFAULT '[]',
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(cluster_id, pool_id, subject_type, subject_id)
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_pool_perms_cluster ON pool_permissions(cluster_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_pool_perms_pool ON pool_permissions(cluster_id, pool_id)
        ''')
        # NS: Feb 2026 - Proxmox Backup Server connections
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pbs_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 8007,
                user TEXT NOT NULL,
                pass_encrypted TEXT DEFAULT '',
                api_token_id TEXT DEFAULT '',
                api_token_secret_encrypted TEXT DEFAULT '',
                fingerprint TEXT DEFAULT '',
                ssl_verify INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                linked_clusters TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        # NS: Feb 2026 - VMware/vCenter integration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vmware_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 443,
                username TEXT NOT NULL,
                pass_encrypted TEXT DEFAULT '',
                server_type TEXT DEFAULT 'vcenter',
                ssl_verify INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                linked_clusters TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        # LW: Feb 2026 - API Tokens for programmatic access without sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                username TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                permissions TEXT DEFAULT '[]',
                expires_at TEXT,
                last_used_at TEXT,
                last_used_ip TEXT,
                created_at TEXT NOT NULL,
                revoked INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(username)
        ''')
        
        # Schema migrations for existing databases
        # Add password_salt column if it doesn't exist (for databases created before this fix)
        try:
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'password_salt' not in columns:
                logging.info("Adding password_salt column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN password_salt TEXT DEFAULT ''")
                    logging.info("Added password_salt column to users table")
                    
                    # Force re-migration of users to populate password_salt
                    logging.info("Will re-migrate users from legacy files...")
                    conn.commit()
                    self._force_remigrate_users = True
                except Exception as e:
                    logging.error(f"Failed to add password_salt column: {e}")
            
            # user prefs columns
            if 'theme' not in columns:
                logging.info("Adding theme column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT ''")
                    logging.info("Added theme column to users table")
                except Exception as e:
                    logging.error(f"Failed to add theme column: {e}")
            
            if 'language' not in columns:
                logging.info("Adding language column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT ''")
                    logging.info("Added language column to users table")
                except Exception as e:
                    logging.error(f"Failed to add language column: {e}")
            
            if 'ui_layout' not in columns:
                logging.info("Adding ui_layout column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN ui_layout TEXT DEFAULT 'modern'")
                    logging.info("Added ui_layout column to users table")
                except Exception as e:
                    logging.error(f"Failed to add ui_layout column: {e}")
            
            # NS: Add enabled column if missing (user disable feature)
            if 'enabled' not in columns:
                logging.info("Adding enabled column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN enabled INTEGER DEFAULT 1")
                    logging.info("Added enabled column to users table")
                except Exception as e:
                    logging.error(f"Failed to add enabled column: {e}")
            
            # MK: Add totp_pending_secret_encrypted column for 2FA setup
            if 'totp_pending_secret_encrypted' not in columns:
                logging.info("Adding totp_pending_secret_encrypted column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN totp_pending_secret_encrypted TEXT DEFAULT ''")
                    logging.info("Added totp_pending_secret_encrypted column to users table")
                except Exception as e:
                    logging.error(f"Failed to add totp_pending_secret_encrypted column: {e}")
            
            # NS: Add taskbar_auto_expand column for user preferences - Feb 2026
            if 'taskbar_auto_expand' not in columns:
                logging.info("Adding taskbar_auto_expand column to users table...")
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN taskbar_auto_expand INTEGER DEFAULT 1")
                    logging.info("Added taskbar_auto_expand column to users table")
                except Exception as e:
                    logging.error(f"Failed to add taskbar_auto_expand column: {e}")
            
            # LW: Feb 2026 - LDAP auth fields
            if 'auth_source' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'local'")
                    logging.info("Added auth_source column to users table")
                except Exception as e:
                    logging.error(f"Failed to add auth_source column: {e}")
            
            if 'display_name' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''")
                    logging.info("Added display_name column to users table")
                except Exception as e:
                    logging.error(f"Failed to add display_name column: {e}")
            
            if 'email' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
                    logging.info("Added email column to users table")
                except Exception as e:
                    logging.error(f"Failed to add email column: {e}")
            
            if 'ldap_dn' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN ldap_dn TEXT DEFAULT ''")
                    logging.info("Added ldap_dn column to users table")
                except Exception as e:
                    logging.error(f"Failed to add ldap_dn column: {e}")
            
            if 'last_ldap_sync' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN last_ldap_sync TEXT DEFAULT ''")
                    logging.info("Added last_ldap_sync column to users table")
                except Exception as e:
                    logging.error(f"Failed to add last_ldap_sync column: {e}")
            
            # NS: Feb 2026 - OIDC and tenant permission fields
            if 'tenant_permissions' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN tenant_permissions TEXT DEFAULT '{}'")
                    logging.info("Added tenant_permissions column to users table")
                except Exception as e:
                    logging.error(f"Failed to add tenant_permissions column: {e}")
            
            if 'denied_permissions' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN denied_permissions TEXT DEFAULT '[]'")
                    logging.info("Added denied_permissions column to users table")
                except Exception as e:
                    logging.error(f"Failed to add denied_permissions column: {e}")
            
            if 'oidc_sub' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN oidc_sub TEXT DEFAULT ''")
                    logging.info("Added oidc_sub column to users table")
                except Exception as e:
                    logging.error(f"Failed to add oidc_sub column: {e}")
            
            if 'last_oidc_sync' not in columns:
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN last_oidc_sync TEXT DEFAULT ''")
                    logging.info("Added last_oidc_sync column to users table")
                except Exception as e:
                    logging.error(f"Failed to add last_oidc_sync column: {e}")
                    
        except Exception as e:
            logging.error(f"Error checking users schema: {e}")
        
        # Schema migration for clusters table - add group_id
        try:
            cursor.execute("PRAGMA table_info(clusters)")
            cluster_columns = [col[1] for col in cursor.fetchall()]
            
            if 'group_id' not in cluster_columns:
                logging.info("Adding group_id column to clusters table...")
                try:
                    cursor.execute("ALTER TABLE clusters ADD COLUMN group_id TEXT DEFAULT NULL")
                    logging.info("Added group_id column to clusters table")
                except Exception as e:
                    logging.error(f"Failed to add group_id column: {e}")
            
            if 'display_name' not in cluster_columns:
                logging.info("Adding display_name column to clusters table...")
                try:
                    cursor.execute("ALTER TABLE clusters ADD COLUMN display_name TEXT DEFAULT ''")
                    logging.info("Added display_name column to clusters table for custom naming")
                except Exception as e:
                    logging.error(f"Failed to add display_name column: {e}")
            
            # MK: Add sort_order for consistent cluster ordering in sidebar
            if 'sort_order' not in cluster_columns:
                logging.info("Adding sort_order column to clusters table...")
                try:
                    cursor.execute("ALTER TABLE clusters ADD COLUMN sort_order INTEGER DEFAULT 0")
                    logging.info("Added sort_order column to clusters table")
                except Exception as e:
                    logging.error(f"Failed to add sort_order column: {e}")
            
            # LW: Add excluded_nodes for node exclusion from balancing (like ProxLB)
            if 'excluded_nodes' not in cluster_columns:
                logging.info("Adding excluded_nodes column to clusters table...")
                try:
                    cursor.execute("ALTER TABLE clusters ADD COLUMN excluded_nodes TEXT DEFAULT '[]'")
                    logging.info("Added excluded_nodes column to clusters table")
                except Exception as e:
                    logging.error(f"Failed to add excluded_nodes column: {e}")
                    
        except Exception as e:
            logging.error(f"Error checking clusters schema: {e}")
        
        # Add HMAC signature column to audit_log for integrity verification (Jan 2026)
        try:
            cursor.execute("PRAGMA table_info(audit_log)")
            audit_columns = [col[1] for col in cursor.fetchall()]
            
            if 'hmac_signature' not in audit_columns:
                logging.info("Adding hmac_signature column to audit_log table for integrity verification...")
                try:
                    cursor.execute("ALTER TABLE audit_log ADD COLUMN hmac_signature TEXT DEFAULT ''")
                    logging.info("Added hmac_signature column to audit_log table")
                except Exception as e:
                    logging.error(f"Failed to add hmac_signature column: {e}")
        except Exception as e:
            logging.error(f"Error checking audit_log schema: {e}")
        
        # MK: enforce was never persisted, value got lost on every restart
        try:
            cursor.execute("PRAGMA table_info(affinity_rules)")
            affinity_columns = [col[1] for col in cursor.fetchall()]

            if 'enforce' not in affinity_columns:
                logging.info("Adding enforce column to affinity_rules table...")
                try:
                    cursor.execute("ALTER TABLE affinity_rules ADD COLUMN enforce INTEGER DEFAULT 0")
                    logging.info("Added enforce column to affinity_rules table")
                except Exception as e:
                    logging.error(f"Failed to add enforce column: {e}")
        except Exception as e:
            logging.error(f"Error checking affinity_rules schema: {e}")

        # MK: Migration - create balancing_excluded_vms table if not exists
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS balancing_excluded_vms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cluster_id TEXT NOT NULL,
                    vmid INTEGER NOT NULL,
                    reason TEXT,
                    created_by TEXT,
                    created_at TEXT,
                    UNIQUE(cluster_id, vmid)
                )
            ''')
            logging.info("Ensured balancing_excluded_vms table exists")
        except Exception as e:
            logging.error(f"Error creating balancing_excluded_vms table: {e}")
        
        # MK: Migration - create update_schedules table if not exists
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS update_schedules (
                    cluster_id TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 0,
                    schedule_type TEXT DEFAULT 'recurring',
                    day TEXT DEFAULT 'sunday',
                    time TEXT DEFAULT '03:00',
                    include_reboot INTEGER DEFAULT 1,
                    skip_evacuation INTEGER DEFAULT 0,
                    skip_up_to_date INTEGER DEFAULT 1,
                    evacuation_timeout INTEGER DEFAULT 1800,
                    last_run TEXT,
                    next_run TEXT,
                    created_by TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            ''')
            logging.info("Ensured update_schedules table exists")
        except Exception as e:
            logging.error(f"Error creating update_schedules table: {e}")

        # NS: Feb 2026 - cross-cluster LB settings for cluster groups
        # allows automatic VM migration between clusters in the same group
        try:
            cursor.execute("PRAGMA table_info(cluster_groups)")
            group_cols = [col[1] for col in cursor.fetchall()]

            if 'cross_cluster_lb_enabled' not in group_cols:
                logging.info("Adding cross-cluster LB columns to cluster_groups...")
                for col_def in [
                    "cross_cluster_lb_enabled INTEGER DEFAULT 0",
                    "cross_cluster_threshold INTEGER DEFAULT 30",
                    "cross_cluster_interval INTEGER DEFAULT 600",
                    "cross_cluster_dry_run INTEGER DEFAULT 1",
                    "cross_cluster_target_storage TEXT DEFAULT ''",
                    "cross_cluster_target_bridge TEXT DEFAULT 'vmbr0'",
                    "cross_cluster_max_migrations INTEGER DEFAULT 1",
                    "cross_cluster_last_run TEXT DEFAULT ''",
                ]:
                    try:
                        cursor.execute(f"ALTER TABLE cluster_groups ADD COLUMN {col_def}")
                    except:
                        pass  # column might already exist from partial migration
                logging.info("Added cross-cluster LB columns to cluster_groups")

            # NS: Feb 2026 - container balancing toggle for cross-cluster LB
            if 'cross_cluster_include_containers' not in group_cols:
                try:
                    cursor.execute("ALTER TABLE cluster_groups ADD COLUMN cross_cluster_include_containers INTEGER DEFAULT 0")
                    logging.info("Added cross_cluster_include_containers column to cluster_groups")
                except:
                    pass
        except Exception as e:
            logging.error(f"Error adding cross-cluster LB columns: {e}")

        # MK: Feb 2026 - cross-cluster replication jobs (snapshot-based DR)
        # native Proxmox replication only works within a cluster, this bridges clusters
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cross_cluster_replications (
                    id TEXT PRIMARY KEY,
                    source_cluster TEXT NOT NULL,
                    target_cluster TEXT NOT NULL,
                    vmid INTEGER NOT NULL,
                    vm_type TEXT DEFAULT 'qemu',
                    schedule TEXT DEFAULT '0 */6 * * *',
                    retention INTEGER DEFAULT 3,
                    target_storage TEXT DEFAULT '',
                    target_bridge TEXT DEFAULT 'vmbr0',
                    enabled INTEGER DEFAULT 1,
                    last_run TEXT,
                    last_status TEXT DEFAULT '',
                    last_error TEXT DEFAULT '',
                    created_by TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT
                )
            ''')
            logging.info("Ensured cross_cluster_replications table exists")
        except Exception as e:
            logging.error(f"Error creating cross_cluster_replications table: {e}")

        # NS: Feb 2026 - Space-efficient LVM COW snapshots managed by PegaProx
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS efficient_snapshots (
                    id TEXT PRIMARY KEY,
                    cluster_id TEXT NOT NULL,
                    node TEXT NOT NULL,
                    vmid INTEGER NOT NULL,
                    vm_type TEXT NOT NULL DEFAULT 'qemu',
                    snapname TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    vg_name TEXT NOT NULL,
                    disks TEXT NOT NULL DEFAULT '[]',
                    total_disk_size_gb REAL DEFAULT 0,
                    total_snap_alloc_gb REAL DEFAULT 0,
                    fs_frozen INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    error_message TEXT DEFAULT '',
                    created_by TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    UNIQUE(cluster_id, vmid, snapname)
                )
            ''')
            logging.info("Ensured efficient_snapshots table exists")
        except Exception as e:
            logging.error(f"Error creating efficient_snapshots table: {e}")

        conn.commit()
        logging.info("DB schema initialized")
    
    def _encrypt(self, data: str) -> str:
        """encrypt sensitive stuff"""
        if not data:
            return data
        
        # try aes256 first (new way)
        if self.aesgcm:
            try:
                nonce = os.urandom(12)
                ciphertext = self.aesgcm.encrypt(nonce, data.encode('utf-8'), None)
                encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
                return f"aes256:{encrypted}"
            except Exception as e:
                logging.error(f"aes encrypt failed: {e}")
        
        # fallback to old fernet
        if self.fernet:
            try:
                return self.fernet.encrypt(data.encode()).decode()
            except Exception as e:
                logging.error(f"fernet failed: {e}")
        
        # ugh no encryption
        logging.warning("no encryption, storing plaintext!!")
        return data
    
    def _decrypt(self, data: str) -> str:
        """decrypt - handles both old and new format"""
        # NS: handles aes256 and old fernet
        if not data:
            return data
        
        # Check for AES-256-GCM format
        if data.startswith('aes256:'):
            if not self.aesgcm:
                logging.error("AES-256-GCM data found but encryption not initialized!")
                return data
            try:
                encrypted = base64.b64decode(data[7:])  # Remove "aes256:" prefix
                nonce = encrypted[:12]  # First 12 bytes are nonce
                ciphertext = encrypted[12:]  # Rest is ciphertext + tag
                plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext.decode('utf-8')
            except Exception as e:
                logging.error(f"AES-256-GCM decryption failed: {e}")
                return data
        
        # Try Fernet (legacy)
        if self.fernet:
            try:
                # Fernet tokens start with 'gAAA' when base64 encoded
                return self.fernet.decrypt(data.encode()).decode()
            except Exception as e:
                # Not a valid Fernet token - might be plain text
                logging.debug(f"Fernet decryption failed (might be plain text): {e}")
                return data
        
        # Return as-is (probably plain text)
        return data
    
    def _needs_reencrypt(self, data: str) -> bool:
        """Check if data needs to be re-encrypted with AES-256-GCM
        
        NS: Returns True for legacy Fernet data
        """
        if not data or not self.aesgcm:
            return False
        # If it's not AES-256-GCM, it needs re-encryption
        return not data.startswith('aes256:')
    
    def _migrate_from_legacy(self):
        """Migrate data from legacy JSON/encrypted files to SQLite"""
        migrated_any = False
        
        # Check if already migrated
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM clusters")
        cluster_count = cursor.fetchone()[0]
        
        # Check if users have proper password_salt (fix for schema migration)
        needs_user_remigration = getattr(self, '_force_remigrate_users', False)
        
        if not needs_user_remigration:
            try:
                cursor.execute("SELECT username, password_salt FROM users LIMIT 1")
                row = cursor.fetchone()
                if row:
                    salt = row[1] if len(row) > 1 else None
                    if not salt or salt == '':  # password_salt is empty or missing
                        logging.warning("Users have empty password_salt - will re-migrate from legacy files")
                        needs_user_remigration = True
            except sqlite3.OperationalError as e:
                # Column might not exist
                logging.warning(f"Could not check password_salt: {e} - will re-migrate")
                needs_user_remigration = True
            except Exception as e:
                logging.error(f"Error checking users: {e}")
        
        if cluster_count > 0 and not needs_user_remigration:
            logging.info("Database already has data, skipping legacy migration")
            return
        
        # Migrate clusters (only if no clusters exist)
        if cluster_count == 0:
            if self._migrate_clusters():
                migrated_any = True
        
        # Migrate users (always if needs_user_remigration or no users)
        if needs_user_remigration or cluster_count == 0:
            # Clear existing users if re-migrating
            if needs_user_remigration:
                try:
                    cursor.execute("DELETE FROM users")
                    self.conn.commit()
                    logging.info("Cleared users table for re-migration")
                except Exception as e:
                    logging.error(f"Error clearing users: {e}")
            
            if self._migrate_users():
                migrated_any = True
        
        # Migrate sessions
        if self._migrate_sessions():
            migrated_any = True
        
        # Migrate audit log
        if self._migrate_audit_log():
            migrated_any = True
        
        # Migrate alerts
        if self._migrate_alerts():
            migrated_any = True
        
        # Migrate VM ACLs
        if self._migrate_vm_acls():
            migrated_any = True
        
        # Migrate affinity rules
        if self._migrate_affinity_rules():
            migrated_any = True
        
        # Migrate tenants
        if self._migrate_tenants():
            migrated_any = True
        
        # Migrate scheduled tasks
        if self._migrate_scheduled_tasks():
            migrated_any = True
        
        # Migrate VM tags
        if self._migrate_vm_tags():
            migrated_any = True
        
        # Migrate migration history
        if self._migrate_migration_history():
            migrated_any = True
        
        # Migrate server settings
        if self._migrate_server_settings():
            migrated_any = True
        
        # Migrate custom roles
        if self._migrate_custom_roles():
            migrated_any = True
        
        # NS: Migrate remaining JSON files - these were scattered everywhere lol
        # MK: should have done this from the start but hindsight is 20/20
        if self._migrate_cluster_alerts():
            migrated_any = True
        
        if self._migrate_esxi_storages():
            migrated_any = True
        
        if self._migrate_storage_clusters():
            migrated_any = True
        
        if self._migrate_cluster_affinity_rules():
            migrated_any = True
        
        # TODO: delete old json files after a few versions? or keep as backup idk - NS
        if migrated_any:
            logging.info("✓ Legacy data migration completed!")
            self.conn.commit()
    
    def _migrate_clusters(self) -> bool:
        """Migrate clusters from encrypted JSON"""
        from pegaprox.core.config import get_fernet
        fernet = get_fernet()
        data = None
        
        # Try encrypted file first
        if fernet and os.path.exists(CONFIG_FILE_ENCRYPTED):
            try:
                with open(CONFIG_FILE_ENCRYPTED, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = fernet.decrypt(encrypted_data)
                data = json.loads(decrypted.decode('utf-8'))
            except Exception as e:
                logging.error(f"Failed to load encrypted clusters: {e}")
        
        # Try unencrypted
        if not data and os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
            except Exception as e:
                logging.error(f"Failed to load clusters.json: {e}")
        
        if not data:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for cluster_id, cluster in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO clusters 
                    (id, name, host, user, pass_encrypted, ssl_verification, 
                     migration_threshold, check_interval, auto_migrate, 
                     balance_containers, balance_local_disks, dry_run, enabled, 
                     ha_enabled, fallback_hosts, ssh_user, ssh_key_encrypted, 
                     ssh_port, ha_settings, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cluster_id,
                    cluster.get('name', ''),
                    cluster.get('host', ''),
                    cluster.get('user', ''),
                    self._encrypt(cluster.get('pass', '')),
                    1 if cluster.get('ssl_verification', True) else 0,
                    cluster.get('migration_threshold', 30),
                    cluster.get('check_interval', 300),
                    1 if cluster.get('auto_migrate', False) else 0,
                    1 if cluster.get('balance_containers', False) else 0,
                    1 if cluster.get('balance_local_disks', False) else 0,
                    1 if cluster.get('dry_run', True) else 0,
                    1 if cluster.get('enabled', True) else 0,
                    1 if cluster.get('ha_enabled', False) else 0,
                    json.dumps(cluster.get('fallback_hosts', [])),
                    cluster.get('ssh_user', ''),
                    self._encrypt(cluster.get('ssh_key', '')),
                    cluster.get('ssh_port', 22),
                    json.dumps(cluster.get('ha_settings', {})),
                    now, now
                ))
            except Exception as e:
                logging.error(f"Failed to migrate cluster {cluster_id}: {e}")
        
        logging.info(f"Migrated {len(data)} clusters to SQLite")
        return True
    
    def _migrate_users(self) -> bool:
        """Migrate users from encrypted file"""
        from pegaprox.core.config import get_fernet
        fernet = get_fernet()
        if not fernet or not os.path.exists(USERS_FILE_ENCRYPTED):
            return False
        
        try:
            with open(USERS_FILE_ENCRYPTED, 'rb') as f:
                encrypted_data = f.read()
            decrypted = fernet.decrypt(encrypted_data)
            data = json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to load users: {e}")
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for username, user in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO users
                    (username, password_salt, password_hash, role, permissions, tenant, 
                     created_at, last_login, password_expiry, 
                     totp_secret_encrypted, totp_enabled, force_password_change)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    user.get('password_salt', ''),
                    user.get('password_hash', user.get('password', '')),
                    user.get('role', 'viewer'),
                    json.dumps(user.get('permissions', [])),
                    user.get('tenant'),
                    user.get('created_at', now),
                    user.get('last_login'),
                    user.get('password_expiry'),
                    self._encrypt(user.get('totp_secret', '')),
                    1 if user.get('totp_enabled', False) else 0,
                    1 if user.get('force_password_change', False) else 0
                ))
            except Exception as e:
                logging.error(f"Failed to migrate user {username}: {e}")
        
        logging.info(f"Migrated {len(data)} users to SQLite")
        return True
    
    def _migrate_sessions(self) -> bool:
        """Migrate sessions from encrypted file"""
        from pegaprox.core.config import get_fernet
        fernet = get_fernet()
        data = None
        
        if fernet and os.path.exists(SESSIONS_FILE_ENCRYPTED):
            try:
                with open(SESSIONS_FILE_ENCRYPTED, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = fernet.decrypt(encrypted_data)
                data = json.loads(decrypted.decode('utf-8'))
            except:
                pass
        
        if not data and os.path.exists(SESSIONS_FILE):
            try:
                with open(SESSIONS_FILE, 'r') as f:
                    data = json.load(f)
            except:
                pass
        
        if not data:
            return False
        
        cursor = self.conn.cursor()
        
        for token, session in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO sessions
                    (token, username, created_at, expires_at, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    token,
                    session.get('user', ''),
                    session.get('created', ''),
                    session.get('expires', ''),
                    session.get('ip', ''),
                    session.get('user_agent', '')
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} sessions to SQLite")
        return True
    
    def _migrate_audit_log(self) -> bool:
        """Migrate audit log from encrypted file"""
        from pegaprox.core.config import get_fernet
        fernet = get_fernet()
        data = None
        
        if fernet and os.path.exists(AUDIT_LOG_FILE_ENCRYPTED):
            try:
                with open(AUDIT_LOG_FILE_ENCRYPTED, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = fernet.decrypt(encrypted_data)
                data = json.loads(decrypted.decode('utf-8'))
            except:
                pass
        
        if not data and os.path.exists(AUDIT_LOG_FILE):
            try:
                with open(AUDIT_LOG_FILE, 'r') as f:
                    data = json.load(f)
            except:
                pass
        
        if not data:
            return False
        
        cursor = self.conn.cursor()
        
        for entry in data:
            try:
                cursor.execute('''
                    INSERT INTO audit_log (timestamp, user, action, details, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    entry.get('timestamp', ''),
                    entry.get('user', ''),
                    entry.get('action', ''),
                    entry.get('details', ''),
                    entry.get('ip', '')
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} audit entries to SQLite")
        return True
    
    def _migrate_alerts(self) -> bool:
        """Migrate alerts from JSON"""
        if not os.path.exists(ALERTS_CONFIG_FILE):
            return False
        
        try:
            with open(ALERTS_CONFIG_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for alert_id, alert in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO alerts
                    (id, cluster_id, node, vmid, type, threshold, enabled, 
                     notify_methods, cooldown, last_triggered, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_id,
                    alert.get('cluster_id'),
                    alert.get('node'),
                    alert.get('vmid'),
                    alert.get('type', ''),
                    alert.get('threshold'),
                    1 if alert.get('enabled', True) else 0,
                    json.dumps(alert.get('notify_methods', [])),
                    alert.get('cooldown', 300),
                    alert.get('last_triggered'),
                    now
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} alerts to SQLite")
        return True
    
    def _migrate_vm_acls(self) -> bool:
        """Migrate VM ACLs from JSON"""
        vm_acls_file = os.path.join(CONFIG_DIR, 'vm_acls.json')
        if not os.path.exists(vm_acls_file):
            return False
        
        try:
            with open(vm_acls_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        
        for cluster_id, vms in data.items():
            for vmid, acl in vms.items():
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO vm_acls (cluster_id, vmid, users, permissions)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        cluster_id,
                        vmid,
                        json.dumps(acl.get('users', [])),
                        json.dumps(acl.get('permissions', []))
                    ))
                except:
                    pass
        
        logging.info(f"Migrated VM ACLs to SQLite")
        return True
    
    def _migrate_affinity_rules(self) -> bool:
        """Migrate affinity rules from JSON"""
        if not os.path.exists(AFFINITY_RULES_FILE):
            return False
        
        try:
            with open(AFFINITY_RULES_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for cluster_id, rules in data.items():
            for rule in rules:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO affinity_rules
                        (id, cluster_id, name, type, vms, enabled, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule.get('id', str(uuid.uuid4())[:8]),
                        cluster_id,
                        rule.get('name', ''),
                        rule.get('type', 'affinity'),
                        json.dumps(rule.get('vms', [])),
                        1 if rule.get('enabled', True) else 0,
                        now
                    ))
                except:
                    pass
        
        logging.info(f"Migrated affinity rules to SQLite")
        return True
    
    def _migrate_tenants(self) -> bool:
        """Migrate tenants from JSON"""
        tenants_file = os.path.join(CONFIG_DIR, 'tenants.json')
        if not os.path.exists(tenants_file):
            return False
        
        try:
            with open(tenants_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for tenant in data:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO tenants (id, name, clusters, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (
                    tenant.get('id', str(uuid.uuid4())[:8]),
                    tenant.get('name', ''),
                    json.dumps(tenant.get('clusters', [])),
                    now
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} tenants to SQLite")
        return True
    
    def _migrate_scheduled_tasks(self) -> bool:
        """Migrate scheduled tasks from JSON"""
        if not os.path.exists(SCHEDULED_TASKS_FILE):
            return False
        
        try:
            with open(SCHEDULED_TASKS_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for task_id, task in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO scheduled_tasks
                    (id, cluster_id, name, task_type, schedule, config, 
                     enabled, last_run, next_run, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    task_id,
                    task.get('cluster_id'),
                    task.get('name', ''),
                    task.get('task_type', ''),
                    task.get('schedule', ''),
                    json.dumps(task.get('config', {})),
                    1 if task.get('enabled', True) else 0,
                    task.get('last_run'),
                    task.get('next_run'),
                    now
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} scheduled tasks to SQLite")
        return True
    
    def _migrate_vm_tags(self) -> bool:
        """Migrate VM tags from JSON"""
        if not os.path.exists(VM_TAGS_FILE):
            return False
        
        try:
            with open(VM_TAGS_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        
        for key, tags in data.items():
            try:
                parts = key.split(':')
                if len(parts) == 2:
                    cluster_id, vmid = parts
                    for tag in tags:
                        tag_name = tag if isinstance(tag, str) else tag.get('name', '')
                        tag_color = tag.get('color', '') if isinstance(tag, dict) else ''
                        cursor.execute('''
                            INSERT OR IGNORE INTO vm_tags (cluster_id, vmid, tag_name, tag_color)
                            VALUES (?, ?, ?, ?)
                        ''', (cluster_id, int(vmid), tag_name, tag_color))
            except:
                pass
        
        logging.info(f"Migrated VM tags to SQLite")
        return True
    
    def _migrate_migration_history(self) -> bool:
        """Migrate migration history from JSON"""
        if not os.path.exists(MIGRATION_HISTORY_FILE):
            return False
        
        try:
            with open(MIGRATION_HISTORY_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        
        for entry in data:
            try:
                cursor.execute('''
                    INSERT INTO migration_history
                    (cluster_id, vmid, vm_name, source_node, target_node, 
                     reason, status, duration_seconds, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.get('cluster_id', ''),
                    entry.get('vmid', 0),
                    entry.get('vm_name', ''),
                    entry.get('source_node', ''),
                    entry.get('target_node', ''),
                    entry.get('reason', ''),
                    entry.get('status', ''),
                    entry.get('duration', 0),
                    entry.get('timestamp', '')
                ))
            except:
                pass
        
        logging.info(f"Migrated {len(data)} migration history entries to SQLite")
        return True
    
    def _migrate_server_settings(self) -> bool:
        """Migrate server settings from JSON"""
        if not os.path.exists(SERVER_SETTINGS_FILE):
            return False
        
        try:
            with open(SERVER_SETTINGS_FILE, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        
        for key, value in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO server_settings (key, value)
                    VALUES (?, ?)
                ''', (key, json.dumps(value) if not isinstance(value, str) else value))
            except:
                pass
        
        logging.info(f"Migrated server settings to SQLite")
        return True
    
    def _migrate_custom_roles(self) -> bool:
        """Migrate custom roles from JSON"""
        roles_file = os.path.join(CONFIG_DIR, 'custom_roles.json')
        if not os.path.exists(roles_file):
            return False
        
        try:
            with open(roles_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for role_name, role_data in data.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO custom_roles (name, permissions, description, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (
                    role_name,
                    json.dumps(role_data.get('permissions', [])),
                    role_data.get('description', ''),
                    now
                ))
            except:
                pass
        
        logging.info(f"Migrated custom roles to SQLite")
        return True
    
    def _migrate_cluster_alerts(self) -> bool:
        """Migrate cluster alerts from JSON to SQLite
        
        NS: These were in cluster_alerts.json before, now in db
        MK: handles both old dict format and new list format
        """
        alerts_file = os.path.join(CONFIG_DIR, 'cluster_alerts.json')
        if not os.path.exists(alerts_file):
            return False
        
        try:
            with open(alerts_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        migrated = 0
        
        for cluster_id, alerts in data.items():
            # Handle list format (new style)
            if isinstance(alerts, list):
                for alert in alerts:
                    try:
                        alert_id = alert.get('id', str(uuid.uuid4())[:8])
                        cursor.execute('''
                            INSERT OR REPLACE INTO cluster_alerts 
                            (cluster_id, alert_type, config, enabled, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            cluster_id,
                            alert_id,
                            json.dumps(alert),
                            1 if alert.get('enabled', True) else 0,
                            now,
                            now
                        ))
                        migrated += 1
                    except:
                        pass
            # Handle dict format (old style)
            elif isinstance(alerts, dict):
                for alert_type, config in alerts.items():
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO cluster_alerts 
                            (cluster_id, alert_type, config, enabled, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            cluster_id,
                            alert_type,
                            json.dumps(config) if isinstance(config, dict) else str(config),
                            1,
                            now,
                            now
                        ))
                        migrated += 1
                    except:
                        pass
        
        logging.info(f"Migrated {migrated} cluster alerts to SQLite")
        return True
    
    def _migrate_esxi_storages(self) -> bool:
        """Migrate ESXi storage config from JSON to SQLite
        
        LW: this esxi stuff was added for vmware migration support
        but those who do really need it for vmware migrations
        """
        esxi_file = os.path.join(CONFIG_DIR, 'esxi_storages.json')
        if not os.path.exists(esxi_file):
            return False
        
        try:
            with open(esxi_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        
        storages = data.get('storages', [])
        for storage in storages:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO esxi_storages 
                    (name, host, username, password_encrypted, datastore, enabled, config)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    storage.get('name', ''),
                    storage.get('host', ''),
                    storage.get('username', ''),
                    storage.get('password', ''),  # Already encrypted in JSON
                    storage.get('datastore', ''),
                    1 if storage.get('enabled', True) else 0,
                    json.dumps(storage.get('config', {}))
                ))
            except:
                pass  # old configs might have weird formats
        
        logging.info(f"Migrated {len(storages)} ESXi storages to SQLite")
        return True
    
    def _migrate_storage_clusters(self) -> bool:
        """Migrate storage clusters from JSON to SQLite
        
        NS: this file was in the wrong place for a while (root dir instead of config)
        so we check both locations just in case
        """
        storage_file = os.path.join(CONFIG_DIR, 'storage_clusters.json')
        if not os.path.exists(storage_file):
            storage_file = 'storage_clusters.json'  # Legacy location oops
        if not os.path.exists(storage_file):
            return False
        
        try:
            with open(storage_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        migrated = 0
        
        for cluster_id, config in data.items():
            clusters = config.get('clusters', [])
            for sc in clusters:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO storage_clusters 
                        (cluster_id, name, storage_type, nodes, config, enabled)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        cluster_id,
                        sc.get('name', ''),
                        sc.get('type', 'ceph'),
                        json.dumps(sc.get('nodes', [])),
                        json.dumps(sc.get('config', {})),
                        1 if sc.get('enabled', True) else 0
                    ))
                    migrated += 1
                except:
                    pass
        
        logging.info(f"Migrated {migrated} storage clusters to SQLite")
        return True
    
    def _migrate_cluster_affinity_rules(self) -> bool:
        """Migrate cluster affinity rules from JSON to SQLite
        
        MK: affinity rules keep VMs together or apart on hosts
        useful for HA setups where you dont want both replicas on same node
        """
        rules_file = os.path.join(CONFIG_DIR, 'cluster_affinity_rules.json')
        if not os.path.exists(rules_file):
            return False
        
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
        except:
            return False
        
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        migrated = 0
        
        for cluster_id, rules in data.items():
            for rule in rules:
                try:
                    # some old rules might not have an id, generate one
                    rule_id = rule.get('id', str(uuid.uuid4()))
                    # NS: handle both 'vms' and 'vm_ids' field names
                    vms_data = rule.get('vms') or rule.get('vm_ids') or []
                    cursor.execute('''
                        INSERT OR REPLACE INTO affinity_rules 
                        (id, cluster_id, name, type, vms, enabled, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule_id,
                        cluster_id,
                        rule.get('name', ''),
                        rule.get('type', 'affinity'),
                        json.dumps(vms_data),
                        1 if rule.get('enabled', True) else 0,
                        rule.get('created_at', now)
                    ))
                    migrated += 1
                except:
                    pass
        
        logging.info(f"Migrated {migrated} cluster affinity rules to SQLite")
        return True
    
    # ========================================
    # CLUSTER OPERATIONS
    # ========================================
    
    def get_all_clusters(self) -> dict:
        """Get all clusters (returns dict like legacy format)"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM clusters')
        
        clusters = {}
        for row in cursor.fetchall():
            clusters[row['id']] = {
                'name': row['name'],
                'host': row['host'],
                'user': row['user'],
                'pass': self._decrypt(row['pass_encrypted']),
                'ssl_verification': bool(row['ssl_verification']),
                'migration_threshold': row['migration_threshold'],
                'check_interval': row['check_interval'],
                'auto_migrate': bool(row['auto_migrate']),
                'balance_containers': bool(row['balance_containers']),
                'balance_local_disks': bool(row['balance_local_disks']),
                'dry_run': bool(row['dry_run']),
                'enabled': bool(row['enabled']),
                'ha_enabled': bool(row['ha_enabled']),
                'fallback_hosts': json.loads(row['fallback_hosts'] or '[]'),
                'ssh_user': row['ssh_user'] or '',
                'ssh_key': self._decrypt(row['ssh_key_encrypted'] or ''),
                'ssh_port': row['ssh_port'] or 22,
                'ha_settings': json.loads(row['ha_settings'] or '{}'),
                'excluded_nodes': json.loads(row['excluded_nodes'] or '[]'),
            }
        
        return clusters
    
    def get_cluster(self, cluster_id: str) -> dict:
        """Get single cluster"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM clusters WHERE id = ?', (cluster_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        # NS: Auto-migrate encrypted fields to AES-256-GCM if needed - Jan 2026
        pass_encrypted = row['pass_encrypted']
        ssh_key_encrypted = row['ssh_key_encrypted'] or ''
        needs_migration = False
        
        if self._needs_reencrypt(pass_encrypted):
            needs_migration = True
        if ssh_key_encrypted and self._needs_reencrypt(ssh_key_encrypted):
            needs_migration = True
        
        # Decrypt values
        decrypted_pass = self._decrypt(pass_encrypted)
        decrypted_ssh_key = self._decrypt(ssh_key_encrypted) if ssh_key_encrypted else ''
        
        # If migration needed, re-encrypt and save
        if needs_migration and self.aesgcm:
            try:
                cursor.execute('''
                    UPDATE clusters SET 
                        pass_encrypted = ?,
                        ssh_key_encrypted = ?,
                        updated_at = ?
                    WHERE id = ?
                ''', (
                    self._encrypt(decrypted_pass),
                    self._encrypt(decrypted_ssh_key) if decrypted_ssh_key else '',
                    datetime.now().isoformat(),
                    cluster_id
                ))
                self.conn.commit()
                logging.info(f"Migrated cluster '{cluster_id}' encryption to AES-256-GCM (Military Grade)")
            except Exception as e:
                logging.warning(f"Failed to migrate cluster encryption: {e}")
        
        return {
            'name': row['name'],
            'host': row['host'],
            'user': row['user'],
            'pass': decrypted_pass,
            'ssl_verification': bool(row['ssl_verification']),
            'migration_threshold': row['migration_threshold'],
            'check_interval': row['check_interval'],
            'auto_migrate': bool(row['auto_migrate']),
            'balance_containers': bool(row['balance_containers']),
            'balance_local_disks': bool(row['balance_local_disks']),
            'dry_run': bool(row['dry_run']),
            'enabled': bool(row['enabled']),
            'ha_enabled': bool(row['ha_enabled']),
            'fallback_hosts': json.loads(row['fallback_hosts'] or '[]'),
            'ssh_user': row['ssh_user'] or '',
            'ssh_key': decrypted_ssh_key,
            'ssh_port': row['ssh_port'] or 22,
            'ha_settings': json.loads(row['ha_settings'] or '{}'),
            'excluded_nodes': json.loads(row['excluded_nodes'] or '[]'),
        }
    
    def save_cluster(self, cluster_id: str, data: dict):
        """Save or update cluster"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO clusters 
            (id, name, host, user, pass_encrypted, ssl_verification, 
             migration_threshold, check_interval, auto_migrate, 
             balance_containers, balance_local_disks, dry_run, enabled, 
             ha_enabled, fallback_hosts, ssh_user, ssh_key_encrypted, 
             ssh_port, ha_settings, excluded_nodes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT created_at FROM clusters WHERE id = ?), ?), ?)
        ''', (
            cluster_id,
            data.get('name', ''),
            data.get('host', ''),
            data.get('user', ''),
            self._encrypt(data.get('pass', '')),
            1 if data.get('ssl_verification', True) else 0,
            data.get('migration_threshold', 30),
            data.get('check_interval', 300),
            1 if data.get('auto_migrate', False) else 0,
            1 if data.get('balance_containers', False) else 0,
            1 if data.get('balance_local_disks', False) else 0,
            1 if data.get('dry_run', True) else 0,
            1 if data.get('enabled', True) else 0,
            1 if data.get('ha_enabled', False) else 0,
            json.dumps(data.get('fallback_hosts', [])),
            data.get('ssh_user', ''),
            self._encrypt(data.get('ssh_key', '')),
            data.get('ssh_port', 22),
            json.dumps(data.get('ha_settings', {})),
            json.dumps(data.get('excluded_nodes', [])),
            cluster_id, now, now
        ))
        self.conn.commit()
    
    def delete_cluster(self, cluster_id: str):
        """Delete cluster"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM clusters WHERE id = ?', (cluster_id,))
        self.conn.commit()
    
    # ========================================
    # USER OPERATIONS
    # ========================================
    
    def get_all_users(self) -> dict:
        """Get all users"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users')
        
        users = {}
        for row in cursor.fetchall():
            # Handle both old schema (no password_salt) and new schema
            row_dict = dict(row)
            password_salt = row_dict.get('password_salt', '')
            password_hash = row_dict.get('password_hash', '')
            
            # If password_salt is missing or empty, check if there's a combined 'password' field
            # This handles migration edge cases
            if not password_salt and 'password' in row_dict:
                # Old format might have combined salt:hash
                combined = row_dict.get('password', '')
                if ':' in combined:
                    password_salt, password_hash = combined.split(':', 1)
            
            users[row['username']] = {
                'password_salt': password_salt,
                'password_hash': password_hash,
                'role': row['role'],
                'permissions': json.loads(row_dict.get('permissions') or '[]'),
                'tenant_id': row_dict.get('tenant') or DEFAULT_TENANT_ID,  # NS: DB stores 'tenant', code uses 'tenant_id'
                'created_at': row_dict.get('created_at'),
                'last_login': row_dict.get('last_login'),
                'password_expiry': row_dict.get('password_expiry'),
                'totp_secret': self._decrypt(row_dict.get('totp_secret_encrypted') or ''),
                'totp_pending_secret': self._decrypt(row_dict.get('totp_pending_secret_encrypted') or ''),  # MK: Load pending 2FA secret
                'totp_enabled': bool(row_dict.get('totp_enabled', 0)),
                'force_password_change': bool(row_dict.get('force_password_change', 0)),
                'enabled': bool(row_dict.get('enabled', 1)),
                # NS: User preferences - these were missing!
                'theme': row_dict.get('theme', ''),
                'language': row_dict.get('language', ''),
                'ui_layout': row_dict.get('ui_layout', 'modern'),
                'taskbar_auto_expand': bool(row_dict.get('taskbar_auto_expand', 1)),
                # LW: Feb 2026 - LDAP fields
                'auth_source': row_dict.get('auth_source', 'local'),
                'display_name': row_dict.get('display_name', ''),
                'email': row_dict.get('email', ''),
                'ldap_dn': row_dict.get('ldap_dn', ''),
                'last_ldap_sync': row_dict.get('last_ldap_sync', ''),
                # NS: Feb 2026 - OIDC and tenant permission fields
                'tenant_permissions': json.loads(row_dict.get('tenant_permissions') or '{}'),
                'denied_permissions': json.loads(row_dict.get('denied_permissions') or '[]'),
                'oidc_sub': row_dict.get('oidc_sub', ''),
                'last_oidc_sync': row_dict.get('last_oidc_sync', ''),
            }
        
        return users
    
    def get_user(self, username: str) -> dict:
        """Get single user"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        # Handle both old schema (no password_salt) and new schema
        row_dict = dict(row)
        password_salt = row_dict.get('password_salt', '')
        password_hash = row_dict.get('password_hash', '')
        
        # If password_salt is missing or empty, check if there's a combined 'password' field
        if not password_salt and 'password' in row_dict:
            combined = row_dict.get('password', '')
            if ':' in combined:
                password_salt, password_hash = combined.split(':', 1)
        
        return {
            'password_salt': password_salt,
            'password_hash': password_hash,
            'role': row_dict.get('role', 'viewer'),
            'permissions': json.loads(row_dict.get('permissions') or '[]'),
            'tenant_id': row_dict.get('tenant') or DEFAULT_TENANT_ID,  # NS: DB stores 'tenant', code uses 'tenant_id'
            'created_at': row_dict.get('created_at'),
            'last_login': row_dict.get('last_login'),
            'password_expiry': row_dict.get('password_expiry'),
            'totp_secret': self._decrypt(row_dict.get('totp_secret_encrypted') or ''),
            'totp_pending_secret': self._decrypt(row_dict.get('totp_pending_secret_encrypted') or ''),  # MK: Load pending 2FA secret
            'totp_enabled': bool(row_dict.get('totp_enabled', 0)),
            'force_password_change': bool(row_dict.get('force_password_change', 0)),
            'enabled': bool(row_dict.get('enabled', 1)),
            'theme': row_dict.get('theme', ''),
            'language': row_dict.get('language', ''),
            'ui_layout': row_dict.get('ui_layout', 'modern'),
            'taskbar_auto_expand': bool(row_dict.get('taskbar_auto_expand', 1)),  # NS: Feb 2026
            'auth_source': row_dict.get('auth_source', 'local'),
            'display_name': row_dict.get('display_name', ''),
            'email': row_dict.get('email', ''),
            'ldap_dn': row_dict.get('ldap_dn', ''),
            'last_ldap_sync': row_dict.get('last_ldap_sync', ''),
            # NS: Feb 2026 - OIDC and tenant permission fields
            'tenant_permissions': json.loads(row_dict.get('tenant_permissions') or '{}'),
            'denied_permissions': json.loads(row_dict.get('denied_permissions') or '[]'),
            'oidc_sub': row_dict.get('oidc_sub', ''),
            'last_oidc_sync': row_dict.get('last_oidc_sync', ''),
        }
    
    def save_user(self, username: str, data: dict):
        """Save or update user"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users
            (username, password_salt, password_hash, role, permissions, tenant, 
             created_at, last_login, password_expiry, 
             totp_secret_encrypted, totp_pending_secret_encrypted, totp_enabled, force_password_change,
             enabled, theme, language, ui_layout, taskbar_auto_expand,
             auth_source, display_name, email, ldap_dn, last_ldap_sync,
             tenant_permissions, denied_permissions, oidc_sub, last_oidc_sync)
            VALUES (?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT created_at FROM users WHERE username = ?), ?), 
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?)
        ''', (
            username,
            data.get('password_salt', ''),
            data.get('password_hash', ''),
            data.get('role', 'viewer'),
            json.dumps(data.get('permissions', [])),
            data.get('tenant_id') or data.get('tenant'),  # NS: Accept both key names
            username, now,
            data.get('last_login'),
            data.get('password_expiry'),
            self._encrypt(data.get('totp_secret', '')),
            self._encrypt(data.get('totp_pending_secret', '')),  # MK: Save pending 2FA secret
            1 if data.get('totp_enabled', False) else 0,
            1 if data.get('force_password_change', False) else 0,
            1 if data.get('enabled', True) else 0,
            data.get('theme', ''),
            data.get('language', ''),
            data.get('ui_layout', 'modern'),
            1 if data.get('taskbar_auto_expand', True) else 0,  # NS: Feb 2026
            data.get('auth_source', 'local'),  # LW: Feb 2026 - LDAP
            data.get('display_name', ''),
            data.get('email', ''),
            data.get('ldap_dn', ''),
            data.get('last_ldap_sync', ''),
            # NS: Feb 2026 - OIDC and tenant permission fields
            json.dumps(data.get('tenant_permissions', {})),
            json.dumps(data.get('denied_permissions', [])),
            data.get('oidc_sub', ''),
            data.get('last_oidc_sync', ''),
        ))
        self.conn.commit()
    
    def save_all_users(self, users: dict):
        """Save all users (for bulk operations)"""
        for username, data in users.items():
            self.save_user(username, data)
    
    def delete_user(self, username: str):
        """Delete user"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        self.conn.commit()
    
    # ========================================
    # SESSION OPERATIONS
    # ========================================
    
    def get_all_sessions(self) -> dict:
        """Get all sessions from database
        
        NOTE: Since v0.6.1, session tokens are stored as SHA-256 hashes.
        This means sessions loaded from DB cannot be validated against
        plaintext tokens - users must re-login after server restart.
        This is a SECURITY FEATURE, not a bug!
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM sessions')
        
        # NS: Return empty dict - old hashed sessions can't be used anyway
        # This forces re-login after restart (more secure)
        sessions = {}
        # Note: We could load the hashes, but they're useless for validation
        # since we can't reverse SHA-256. Just return empty.
        logging.debug(f"Sessions in DB will be cleared (tokens are hashed, can't validate)")
        
        # Clean up old sessions from DB
        cursor.execute('DELETE FROM sessions')
        self.conn.commit()
        
        return sessions
    
    def get_session(self, token: str) -> dict:
        """Get single session"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM sessions WHERE token = ?', (token,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'user': row['username'],
            'created': row['created_at'],
            'expires': row['expires_at'],
            'ip': row['ip_address'],
            'user_agent': row['user_agent'],
        }
    
    def save_session(self, token: str, data: dict):
        """Save session
        
        NS: Session tokens are hashed before storing in DB for security!
        If someone steals the DB, they can't hijack sessions.
        Trade-off: Sessions don't survive server restarts (users must re-login)
        """
        cursor = self.conn.cursor()
        
        # Hash the token - even if DB is stolen, tokens can't be used
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sessions
            (token, username, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            token_hash,  # Store hash, not plaintext token!
            data.get('user', ''),
            data.get('created', ''),
            data.get('expires', ''),
            data.get('ip', ''),
            data.get('user_agent', '')
        ))
        self.conn.commit()
    
    def delete_session(self, token: str):
        """Delete session"""
        cursor = self.conn.cursor()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        cursor.execute('DELETE FROM sessions WHERE token = ?', (token_hash,))
        self.conn.commit()
    
    def delete_expired_sessions(self):
        """Delete expired sessions"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
        self.conn.commit()
    
    def save_all_sessions(self, sessions: dict):
        """Save all sessions"""
        for token, data in sessions.items():
            self.save_session(token, data)
    
    # ========================================
    # AUDIT LOG OPERATIONS (with HMAC Integrity)
    # ========================================
    
    def _generate_audit_hmac(self, timestamp: str, user: str, action: str, details: str, ip: str) -> str:
        """Generate HMAC signature for audit entry (tamper detection)"""
        if not self.aes_key:
            return ''
        
        # Create canonical string for signing
        data = f"{timestamp}|{user or ''}|{action}|{details or ''}|{ip or ''}"
        
        # Use HMAC-SHA256 with AES key as secret
        signature = hmac.new(
            self.aes_key,
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _verify_audit_hmac(self, entry: dict) -> bool:
        """Verify HMAC signature of an audit entry"""
        if not self.aes_key:
            return True  # Can't verify without key
        
        stored_sig = entry.get('hmac_signature', '')
        if not stored_sig:
            return False  # No signature = potentially tampered or old entry
        
        # Regenerate signature
        expected_sig = self._generate_audit_hmac(
            entry.get('timestamp', ''),
            entry.get('user', ''),
            entry.get('action', ''),
            entry.get('details', ''),
            entry.get('ip_address', '')
        )
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_sig, expected_sig)
    
    def add_audit_entry(self, user: str, action: str, details: str = '', ip: str = ''):
        """Add audit log entry with HMAC signature for integrity verification"""
        cursor = self.conn.cursor()
        timestamp = datetime.now().isoformat()
        
        # Generate HMAC signature for tamper detection
        signature = self._generate_audit_hmac(timestamp, user, action, details, ip)
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, user, action, details, ip_address, hmac_signature)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, user, action, details, ip, signature))
        self.conn.commit()
    
    def get_audit_log(self, limit: int = 1000, user: str = None, action: str = None, verify_integrity: bool = False) -> list:
        """Get audit log entries, optionally verifying HMAC integrity"""
        cursor = self.conn.cursor()
        
        query = 'SELECT * FROM audit_log'
        params = []
        conditions = []
        
        if user:
            conditions.append('user = ?')
            params.append(user)
        if action:
            conditions.append('action LIKE ?')
            params.append(f'%{action}%')
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        entries = [dict(row) for row in cursor.fetchall()]
        
        # Optionally verify integrity
        if verify_integrity:
            for entry in entries:
                entry['integrity_verified'] = self._verify_audit_hmac(entry)
        
        return entries
    
    def verify_audit_log_integrity(self) -> dict:
        """Verify integrity of entire audit log - returns statistics"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
        
        total = 0
        verified = 0
        unsigned = 0
        tampered = 0
        
        for row in cursor.fetchall():
            entry = dict(row)
            total += 1
            
            if not entry.get('hmac_signature'):
                unsigned += 1  # Old entry without signature
            elif self._verify_audit_hmac(entry):
                verified += 1
            else:
                tampered += 1
                logging.warning(f"AUDIT LOG INTEGRITY VIOLATION: Entry ID {entry.get('id')} may have been tampered!")
        
        return {
            'total_entries': total,
            'verified': verified,
            'unsigned': unsigned,
            'potentially_tampered': tampered,
            'integrity_percentage': round((verified / total * 100) if total > 0 else 100, 2)
        }
    
    def cleanup_audit_log(self, days: int = 90):
        """Remove audit entries older than specified days"""
        cursor = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute('DELETE FROM audit_log WHERE timestamp < ?', (cutoff,))
        deleted = cursor.rowcount
        self.conn.commit()
        return deleted
    
    # ========================================
    # ALERT OPERATIONS
    # ========================================
    
    def get_all_alerts(self) -> dict:
        """Get all alerts"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM alerts')
        
        alerts = {}
        for row in cursor.fetchall():
            alerts[row['id']] = {
                'id': row['id'],
                'cluster_id': row['cluster_id'],
                'node': row['node'],
                'vmid': row['vmid'],
                'type': row['type'],
                'threshold': row['threshold'],
                'enabled': bool(row['enabled']),
                'notify_methods': json.loads(row['notify_methods'] or '[]'),
                'cooldown': row['cooldown'],
                'last_triggered': row['last_triggered'],
            }
        
        return alerts
    
    def save_alert(self, alert_id: str, data: dict):
        """Save alert"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO alerts
            (id, cluster_id, node, vmid, type, threshold, enabled, 
             notify_methods, cooldown, last_triggered, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT created_at FROM alerts WHERE id = ?), ?))
        ''', (
            alert_id,
            data.get('cluster_id'),
            data.get('node'),
            data.get('vmid'),
            data.get('type', ''),
            data.get('threshold'),
            1 if data.get('enabled', True) else 0,
            json.dumps(data.get('notify_methods', [])),
            data.get('cooldown', 300),
            data.get('last_triggered'),
            alert_id, now
        ))
        self.conn.commit()
    
    def delete_alert(self, alert_id: str):
        """Delete alert"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
        self.conn.commit()
    
    def save_all_alerts(self, alerts: dict):
        """Save all alerts"""
        for alert_id, data in alerts.items():
            self.save_alert(alert_id, data)
    
    # ========================================
    # VM ACL OPERATIONS
    # ========================================
    
    def get_all_vm_acls(self) -> dict:
        """Get all VM ACLs"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM vm_acls')
        
        acls = {}
        for row in cursor.fetchall():
            cluster_id = row['cluster_id']
            if cluster_id not in acls:
                acls[cluster_id] = {}
            acls[cluster_id][row['vmid']] = {
                'users': json.loads(row['users'] or '[]'),
                'permissions': json.loads(row['permissions'] or '[]'),
            }
        
        return acls
    
    def save_vm_acl(self, cluster_id: str, vmid: str, data: dict):
        """Save VM ACL"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO vm_acls (cluster_id, vmid, users, permissions)
            VALUES (?, ?, ?, ?)
        ''', (
            cluster_id,
            vmid,
            json.dumps(data.get('users', [])),
            json.dumps(data.get('permissions', []))
        ))
        self.conn.commit()
    
    def save_all_vm_acls(self, acls: dict):
        """Save all VM ACLs"""
        for cluster_id, vms in acls.items():
            for vmid, data in vms.items():
                self.save_vm_acl(cluster_id, vmid, data)
    
    def delete_vm_acl(self, cluster_id: str, vmid: int) -> bool:
        """Delete a VM ACL entry from the database
        
        NS: This was missing! save_all_vm_acls only adds/updates, never deletes.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM vm_acls WHERE cluster_id = ? AND vmid = ?',
                          (cluster_id, str(vmid)))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logging.error(f"Failed to delete VM ACL: {e}")
            return False
    
    # ========================================
    # POOL PERMISSIONS - MK Jan 2026
    # ========================================
    
    def get_pool_permissions(self, cluster_id: str, pool_id: str = None) -> List[Dict]:
        """Get pool permissions, optionally filtered by pool_id"""
        cursor = self.conn.cursor()
        if pool_id:
            cursor.execute('''
                SELECT * FROM pool_permissions 
                WHERE cluster_id = ? AND pool_id = ?
            ''', (cluster_id, pool_id))
        else:
            cursor.execute('''
                SELECT * FROM pool_permissions WHERE cluster_id = ?
            ''', (cluster_id,))
        
        rows = cursor.fetchall()
        result = []
        for row in rows:
            result.append({
                'id': row[0],
                'cluster_id': row[1],
                'pool_id': row[2],
                'subject_type': row[3],  # 'user' or 'group'
                'subject_id': row[4],    # username or group name
                'permissions': json.loads(row[5]) if row[5] else [],
                'created_at': row[6],
                'updated_at': row[7]
            })
        return result
    
    def save_pool_permission(self, cluster_id: str, pool_id: str, subject_type: str, 
                            subject_id: str, permissions: List[str]) -> bool:
        """Save or update pool permission"""
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO pool_permissions (cluster_id, pool_id, subject_type, subject_id, permissions, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cluster_id, pool_id, subject_type, subject_id) 
                DO UPDATE SET permissions = ?, updated_at = ?
            ''', (cluster_id, pool_id, subject_type, subject_id, json.dumps(permissions), now, now,
                  json.dumps(permissions), now))
            self.conn.commit()
            return True
        except Exception as e:
            logging.error(f"Failed to save pool permission: {e}")
            return False
    
    def delete_pool_permission(self, cluster_id: str, pool_id: str, subject_type: str, subject_id: str) -> bool:
        """Delete a pool permission"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                DELETE FROM pool_permissions 
                WHERE cluster_id = ? AND pool_id = ? AND subject_type = ? AND subject_id = ?
            ''', (cluster_id, pool_id, subject_type, subject_id))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logging.error(f"Failed to delete pool permission: {e}")
            return False
    
    def get_user_pool_permissions(self, cluster_id: str, username: str, groups: List[str] = None) -> Dict[str, List[str]]:
        """Get all pool permissions for a user (including via group membership)
        Returns: {pool_id: [permissions]}
        """
        cursor = self.conn.cursor()
        
        # Get direct user permissions
        cursor.execute('''
            SELECT pool_id, permissions FROM pool_permissions 
            WHERE cluster_id = ? AND subject_type = 'user' AND subject_id = ?
        ''', (cluster_id, username))
        
        result = {}
        for row in cursor.fetchall():
            pool_id = row[0]
            perms = json.loads(row[1]) if row[1] else []
            result[pool_id] = perms
        
        # Get group permissions
        if groups:
            for group in groups:
                cursor.execute('''
                    SELECT pool_id, permissions FROM pool_permissions 
                    WHERE cluster_id = ? AND subject_type = 'group' AND subject_id = ?
                ''', (cluster_id, group))
                
                for row in cursor.fetchall():
                    pool_id = row[0]
                    perms = json.loads(row[1]) if row[1] else []
                    if pool_id in result:
                        # Merge permissions (union)
                        result[pool_id] = list(set(result[pool_id] + perms))
                    else:
                        result[pool_id] = perms
        
        return result
    
    # ========================================
    # KEY ROTATION (HIPAA/ISO Compliance)
    # ========================================
    
    def rotate_encryption_key(self) -> dict:
        """Rotate the AES-256 encryption key and re-encrypt all data
        
        This is required for HIPAA/ISO 27001 compliance (periodic key rotation).
        Process:
        1. Generate new AES-256 key
        2. Decrypt all encrypted data with old key
        3. Re-encrypt with new key
        4. Replace old key file
        
        Returns statistics about the rotation.
        """
        if not ENCRYPTION_AVAILABLE or not self.aesgcm:
            return {'error': 'Encryption not available'}
        
        aes_key_file = os.path.join(CONFIG_DIR, '.pegaprox_aes256.key')
        
        # Load old key
        with open(aes_key_file, 'rb') as f:
            old_key = f.read()
        old_aesgcm = AESGCM(old_key)
        
        # Generate new key
        new_key = os.urandom(32)  # 256 bits
        new_aesgcm = AESGCM(new_key)
        
        stats = {
            'users_rotated': 0,
            'clusters_rotated': 0,
            'sessions_rotated': 0,
            'errors': []
        }
        
        try:
            cursor = self.conn.cursor()
            
            # 1. Rotate user secrets (totp_secret_encrypted)
            cursor.execute('SELECT username, totp_secret_encrypted FROM users WHERE totp_secret_encrypted IS NOT NULL AND totp_secret_encrypted != ""')
            for row in cursor.fetchall():
                try:
                    encrypted = row['totp_secret_encrypted']
                    if encrypted and encrypted.startswith('aes256:'):
                        # Decrypt with old key
                        decrypted = self._decrypt_with_key(encrypted, old_aesgcm)
                        # Re-encrypt with new key
                        new_encrypted = self._encrypt_with_key(decrypted, new_aesgcm)
                        # Update
                        cursor.execute('UPDATE users SET totp_secret_encrypted = ? WHERE username = ?',
                                     (new_encrypted, row['username']))
                        stats['users_rotated'] += 1
                except Exception as e:
                    stats['errors'].append(f"User {row['username']}: {str(e)}")
            
            # 2. Rotate cluster credentials
            cursor.execute('SELECT id, password_encrypted FROM clusters WHERE password_encrypted IS NOT NULL AND password_encrypted != ""')
            for row in cursor.fetchall():
                try:
                    encrypted = row['password_encrypted']
                    if encrypted and encrypted.startswith('aes256:'):
                        decrypted = self._decrypt_with_key(encrypted, old_aesgcm)
                        new_encrypted = self._encrypt_with_key(decrypted, new_aesgcm)
                        cursor.execute('UPDATE clusters SET password_encrypted = ? WHERE id = ?',
                                     (new_encrypted, row['id']))
                        stats['clusters_rotated'] += 1
                except Exception as e:
                    stats['errors'].append(f"Cluster {row['id']}: {str(e)}")
            
            # Also rotate SSH keys and API tokens if present
            cursor.execute('SELECT id, ssh_key_encrypted, api_token_encrypted FROM clusters')
            for row in cursor.fetchall():
                try:
                    updated = False
                    ssh_key = row['ssh_key_encrypted']
                    api_token = row['api_token_encrypted']
                    
                    if ssh_key and ssh_key.startswith('aes256:'):
                        decrypted = self._decrypt_with_key(ssh_key, old_aesgcm)
                        new_encrypted = self._encrypt_with_key(decrypted, new_aesgcm)
                        cursor.execute('UPDATE clusters SET ssh_key_encrypted = ? WHERE id = ?',
                                     (new_encrypted, row['id']))
                        updated = True
                    
                    if api_token and api_token.startswith('aes256:'):
                        decrypted = self._decrypt_with_key(api_token, old_aesgcm)
                        new_encrypted = self._encrypt_with_key(decrypted, new_aesgcm)
                        cursor.execute('UPDATE clusters SET api_token_encrypted = ? WHERE id = ?',
                                     (new_encrypted, row['id']))
                        updated = True
                except Exception as e:
                    stats['errors'].append(f"Cluster secrets {row['id']}: {str(e)}")
            
            # 3. Rotate session data if encrypted
            cursor.execute('SELECT token, data_encrypted FROM sessions WHERE data_encrypted IS NOT NULL AND data_encrypted != ""')
            for row in cursor.fetchall():
                try:
                    encrypted = row['data_encrypted']
                    if encrypted and encrypted.startswith('aes256:'):
                        decrypted = self._decrypt_with_key(encrypted, old_aesgcm)
                        new_encrypted = self._encrypt_with_key(decrypted, new_aesgcm)
                        cursor.execute('UPDATE sessions SET data_encrypted = ? WHERE token = ?',
                                     (new_encrypted, row['token']))
                        stats['sessions_rotated'] += 1
                except Exception as e:
                    stats['errors'].append(f"Session: {str(e)}")
            
            self.conn.commit()
            
            # 4. Save new key (backup old key first)
            backup_file = aes_key_file + f'.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            with open(backup_file, 'wb') as f:
                f.write(old_key)
            os.chmod(backup_file, 0o600)
            
            with open(aes_key_file, 'wb') as f:
                f.write(new_key)
            os.chmod(aes_key_file, 0o600)
            
            # 5. Update in-memory key
            self.aes_key = new_key
            self.aesgcm = new_aesgcm
            
            stats['success'] = True
            stats['key_backup'] = backup_file
            stats['rotated_at'] = datetime.now().isoformat()
            
            logging.info(f"Key rotation completed: {stats['users_rotated']} users, {stats['clusters_rotated']} clusters, {stats['sessions_rotated']} sessions")
            
        except Exception as e:
            stats['success'] = False
            stats['error'] = str(e)
            logging.error(f"Key rotation failed: {e}")
            self.conn.rollback()
        
        return stats
    
    def _encrypt_with_key(self, data: str, aesgcm) -> str:
        """Encrypt data with specific AESGCM key"""
        if not data:
            return data
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
        return f"aes256:{encrypted}"
    
    def _decrypt_with_key(self, data: str, aesgcm) -> str:
        """Decrypt data with specific AESGCM key"""
        if not data:
            return data
        if data.startswith('aes256:'):
            encrypted_data = base64.b64decode(data[7:])
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        return data
    
    def get_key_info(self) -> dict:
        """Get information about the current encryption key"""
        aes_key_file = os.path.join(CONFIG_DIR, '.pegaprox_aes256.key')
        
        if not os.path.exists(aes_key_file):
            return {'exists': False}
        
        stat = os.stat(aes_key_file)
        
        # Find backup files
        backups = []
        for f in os.listdir(CONFIG_DIR):
            if f.startswith('.pegaprox_aes256.key.backup'):
                backup_path = os.path.join(CONFIG_DIR, f)
                backup_stat = os.stat(backup_path)
                backups.append({
                    'filename': f,
                    'created': datetime.fromtimestamp(backup_stat.st_mtime).isoformat()
                })
        
        return {
            'exists': True,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'algorithm': 'AES-256-GCM',
            'key_size_bits': 256,
            'backups': sorted(backups, key=lambda x: x['created'], reverse=True)
        }
    
    # ========================================
    # AFFINITY RULES OPERATIONS
    # ========================================
    
    def get_affinity_rules(self, cluster_id: str = None) -> dict:
        """Get affinity rules"""
        cursor = self.conn.cursor()
        
        if cluster_id:
            cursor.execute('SELECT * FROM affinity_rules WHERE cluster_id = ?', (cluster_id,))
        else:
            cursor.execute('SELECT * FROM affinity_rules')
        
        rules = {}
        for row in cursor.fetchall():
            cid = row['cluster_id']
            if cid not in rules:
                rules[cid] = []
            vms_list = json.loads(row['vms'] or '[]')
            rules[cid].append({
                'id': row['id'],
                'name': row['name'],
                'type': row['type'],
                'vms': vms_list,
                'vm_ids': vms_list,  # MK: frontend expects vm_ids
                'enabled': bool(row['enabled']),
                'enforce': bool(row.get('enforce', 0)),
            })

        return rules
    
    def save_affinity_rule(self, rule_id: str, cluster_id: str, data: dict):
        """Save affinity rule"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        vms_data = data.get('vms') or data.get('vm_ids', [])  # handle both field names

        cursor.execute('''
            INSERT OR REPLACE INTO affinity_rules
            (id, cluster_id, name, type, vms, enabled, enforce, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM affinity_rules WHERE id = ?), ?))
        ''', (
            rule_id,
            cluster_id,
            data.get('name', ''),
            data.get('type', 'affinity'),
            json.dumps(vms_data),
            1 if data.get('enabled', True) else 0,
            1 if data.get('enforce', False) else 0,
            rule_id, now
        ))
        self.conn.commit()
    
    def delete_affinity_rule(self, rule_id: str):
        """Delete affinity rule"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM affinity_rules WHERE id = ?', (rule_id,))
        self.conn.commit()
    
    def save_all_affinity_rules(self, rules: dict):
        """Save all affinity rules"""
        for cluster_id, cluster_rules in rules.items():
            for rule in cluster_rules:
                self.save_affinity_rule(rule.get('id', str(uuid.uuid4())[:8]), cluster_id, rule)
    
    # ========================================
    # SERVER SETTINGS OPERATIONS
    # ========================================
    
    def get_server_settings(self) -> dict:
        """Get all server settings"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM server_settings')
        
        settings = {}
        for row in cursor.fetchall():
            try:
                settings[row['key']] = json.loads(row['value'])
            except:
                settings[row['key']] = row['value']
        
        return settings
    
    def get_server_setting(self, key: str, default=None):
        """Get single server setting"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM server_settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        
        if not row:
            return default
        
        try:
            return json.loads(row['value'])
        except:
            return row['value']
    
    def save_server_setting(self, key: str, value):
        """Save server setting - always JSON encode to ensure consistent retrieval"""
        cursor = self.conn.cursor()
        # Always JSON encode the value for consistent storage and retrieval
        json_value = json.dumps(value)
        cursor.execute('''
            INSERT OR REPLACE INTO server_settings (key, value)
            VALUES (?, ?)
        ''', (key, json_value))
        self.conn.commit()
    
    def save_server_settings(self, settings: dict):
        """Save all server settings"""
        for key, value in settings.items():
            self.save_server_setting(key, value)
    
    # ========================================
    # TENANTS OPERATIONS
    # ========================================
    
    def get_all_tenants(self) -> list:
        """Get all tenants"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM tenants')
        
        return [{
            'id': row['id'],
            'name': row['name'],
            'clusters': json.loads(row['clusters'] or '[]'),
        } for row in cursor.fetchall()]
    
    def save_tenant(self, tenant_id: str, data: dict):
        """Save tenant"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO tenants (id, name, clusters, created_at)
            VALUES (?, ?, ?, COALESCE((SELECT created_at FROM tenants WHERE id = ?), ?))
        ''', (
            tenant_id,
            data.get('name', ''),
            json.dumps(data.get('clusters', [])),
            tenant_id, now
        ))
        self.conn.commit()
    
    def delete_tenant(self, tenant_id: str):
        """Delete tenant"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM tenants WHERE id = ?', (tenant_id,))
        self.conn.commit()
    
    def save_all_tenants(self, tenants: list):
        """Save all tenants"""
        for tenant in tenants:
            self.save_tenant(tenant.get('id', str(uuid.uuid4())[:8]), tenant)
    
    # Generic query methods for custom tables like scripts
    def execute(self, sql: str, params: tuple = ()):
        """Execute SQL statement (CREATE, INSERT, UPDATE, DELETE)"""
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        self.conn.commit()
    
    def query(self, sql: str, params: tuple = ()) -> list:
        """Execute SQL query and return all results as list of Row objects"""
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute(sql, params)
        return cursor.fetchall()
    
    def query_one(self, sql: str, params: tuple = ()):
        """Execute SQL query and return first result or None"""
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute(sql, params)
        return cursor.fetchone()

    # NS: Feb 2026 - efficient snapshot CRUD (was part of the manager before the split)
    def save_efficient_snapshot(self, snap_data: dict):
        """Save a new efficient snapshot record to the database."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO efficient_snapshots
            (id, cluster_id, node, vmid, vm_type, snapname, description, vg_name,
             disks, total_disk_size_gb, total_snap_alloc_gb, fs_frozen, status,
             error_message, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            snap_data['id'],
            snap_data['cluster_id'],
            snap_data['node'],
            snap_data['vmid'],
            snap_data.get('vm_type', 'qemu'),
            snap_data['snapname'],
            snap_data.get('description', ''),
            snap_data['vg_name'],
            json.dumps(snap_data.get('disks', [])),
            snap_data.get('total_disk_size_gb', 0),
            snap_data.get('total_snap_alloc_gb', 0),
            1 if snap_data.get('fs_frozen') else 0,
            snap_data.get('status', 'active'),
            snap_data.get('error_message', ''),
            snap_data.get('created_by', ''),
            now,
            now
        ))
        self.conn.commit()

    def get_efficient_snapshots(self, cluster_id: str, vmid: int) -> list:
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute(
            'SELECT * FROM efficient_snapshots WHERE cluster_id = ? AND vmid = ? ORDER BY created_at DESC',
            (cluster_id, vmid)
        )
        rows = cursor.fetchall()
        return [self._row_to_efficient_snapshot(row) for row in rows]

    def get_efficient_snapshot(self, snap_id: str) -> dict:
        # MK: returns None if not found
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute('SELECT * FROM efficient_snapshots WHERE id = ?', (snap_id,))
        row = cursor.fetchone()
        return self._row_to_efficient_snapshot(row) if row else None

    def delete_efficient_snapshot(self, snap_id: str):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM efficient_snapshots WHERE id = ?', (snap_id,))
        self.conn.commit()

    def update_efficient_snapshot_status(self, snap_id: str, status: str, error_message: str = ''):
        # NS: status can be active/merging/invalidated/error
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            'UPDATE efficient_snapshots SET status = ?, error_message = ?, updated_at = ? WHERE id = ?',
            (status, error_message, now, snap_id)
        )
        self.conn.commit()

    def update_efficient_snapshot_disks(self, snap_id: str, disks: list, total_snap_alloc_gb: float = None):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        if total_snap_alloc_gb is not None:
            cursor.execute(
                'UPDATE efficient_snapshots SET disks = ?, total_snap_alloc_gb = ?, updated_at = ? WHERE id = ?',
                (json.dumps(disks), total_snap_alloc_gb, now, snap_id)
            )
        else:
            cursor.execute(
                'UPDATE efficient_snapshots SET disks = ?, updated_at = ? WHERE id = ?',
                (json.dumps(disks), now, snap_id)
            )
        self.conn.commit()

    def get_all_efficient_snapshots(self, cluster_id: str) -> list:
        """Get all efficient snapshots for a given cluster, ordered by creation date."""
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute(
            'SELECT * FROM efficient_snapshots WHERE cluster_id = ? ORDER BY created_at DESC',
            (cluster_id,)
        )
        rows = cursor.fetchall()
        return [self._row_to_efficient_snapshot(row) for row in rows]

    def _row_to_efficient_snapshot(self, row) -> dict:
        return {
            'id': row['id'],
            'cluster_id': row['cluster_id'],
            'node': row['node'],
            'vmid': row['vmid'],
            'vm_type': row['vm_type'],
            'snapname': row['snapname'],
            'description': row['description'],
            'vg_name': row['vg_name'],
            'disks': json.loads(row['disks'] or '[]'),
            'total_disk_size_gb': row['total_disk_size_gb'],
            'total_snap_alloc_gb': row['total_snap_alloc_gb'],
            'fs_frozen': bool(row['fs_frozen']),
            'status': row['status'],
            'error_message': row['error_message'],
            'created_by': row['created_by'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }


# Global database instance
_db = None

def get_db() -> PegaProxDB:
    """Get database instance (singleton)"""
    global _db
    if _db is None:
        _db = PegaProxDB()
    return _db

