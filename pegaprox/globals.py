# -*- coding: utf-8 -*-
"""
PegaProx Globals - Layer 1
Shared mutable state containers. Only plain Python, no pegaprox imports.
"""

import os
import threading

# NS: all the global state was scattered across 51k lines before, at least now its in one place

# Global cluster managers: cluster_id -> PegaProxManager
cluster_managers = {}

# PBS managers: pbs_id -> PBSManager
pbs_managers = {}

# VMware managers: vmware_id -> VMwareManager
vmware_managers = {}

# Active sessions: session_id -> {user, created_at, last_activity, role}
active_sessions = {}
sessions_lock = threading.Lock()  # NS: Feb 2026 - SECURITY: protect session dict mutations

# User database (in-memory)
users_db = {}

# Audit log (in-memory cache)
audit_log = []

# Login brute force tracking
login_attempts_by_ip = {}
login_attempts_by_user = {}

# Auth action rate limiting
_auth_action_attempts = {}
_auth_action_lock = threading.Lock()

# Session secret
SESSION_SECRET = None

# API rate limiting state
api_request_counts = {}
api_rate_limit_lock = threading.Lock()

# SSH connection management
# NS: was 'BoundedSemaphore' because regular Semaphore doesn't raise on over-release
_ssh_semaphore = None  # Initialized in init_ssh_semaphore()
_ssh_active_connections = {'normal': 0, 'ha': 0}
_ssh_connection_lock = threading.Lock()

def init_ssh_semaphore(max_concurrent):
    global _ssh_semaphore
    _ssh_semaphore = threading.BoundedSemaphore(max_concurrent)

# Task user tracking
task_pegaprox_users_cache = {}
task_pegaprox_users_lock = threading.Lock()

# CORS
_cors_origins_env = os.environ.get('PEGAPROX_ALLOWED_ORIGINS', '')
_auto_allowed_origins = set()

# WebSocket clients
ws_clients = {}
ws_clients_lock = threading.Lock()

# SSE tokens and clients
sse_tokens = {}
sse_tokens_lock = threading.Lock()
sse_clients = {}
sse_clients_lock = threading.Lock()

# Storage balancing
storage_clusters_config = {}
_storage_config_lock = threading.RLock()
_migration_lock = threading.Lock()
_cache_lock = threading.Lock()
active_auto_migrations = {}

# ESXi storages
esxi_storages = {}

# IP whitelisting
_ip_whitelist_enabled = False
_ip_whitelist = set()
_ip_blacklist = set()

# Custom roles cache
_custom_roles_cache = None
_custom_roles_cache_time = 0

# VM ACLs cache
_vm_acls_cache = None
_vm_acls_cache_time = 0

# Pool membership cache
_pool_cache = {}
_pool_cache_lock = threading.Lock()
_pool_cache_time = {}

# Background thread references
_broadcast_thread = None
_alert_thread = None
_alert_running = False
_alert_last_sent = {}
_password_expiry_thread = None
_password_expiry_running = False
_password_expiry_last_check = {}
_scheduler_thread = None
_scheduler_running = False
_xclb_thread = None
_xclb_running = False

# URL download tracking
_url_downloads = {}

# V2P migrations
_v2p_migrations = {}
