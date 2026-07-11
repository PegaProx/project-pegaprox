# PegaProx authorization / tenant-isolation regression suite — shared harness.
#
# These tests exercise the RBAC layer (pegaprox/utils/rbac.py) directly against a
# throwaway encrypted DB — NO live PVE/ESXi cluster is needed, because
# user_can_access_vm / get_user_clusters / has_permission only read the DB
# (users, tenants, vm_acls, pool_permissions). The point is a permanent guard so
# the BOLA / tenant-isolation invariants that were historically fixed by hand
# (#490/#493/#495/#555 …) cannot silently regress on a refactor.
#
# Harness: gevent monkeypatch first, then point pegaprox.core.db at a per-test
# temp dir (CONFIG_DIR is a relative constant with no env override), reset the DB
# singleton, and seed via the real db.save_* methods.

import gevent.monkey
gevent.monkey.patch_all()

import os
import types
import tempfile
import shutil

import pytest

DEFAULT_TENANT = 'default'


@pytest.fixture
def db():
    """A fresh, isolated, throwaway PegaProxDB pointed at a temp dir."""
    tmp = tempfile.mkdtemp(prefix='pp_authz_test_')
    import pegaprox.core.db as dbmod

    # db.py binds CONFIG_DIR / DATABASE_FILE / KEY_FILE at import from constants;
    # __init__ reads DATABASE_FILE and _init_encryption reads CONFIG_DIR at call
    # time from these module globals — so redirecting them here is enough.
    _orig = (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE)
    dbmod.CONFIG_DIR = tmp
    dbmod.DATABASE_FILE = os.path.join(tmp, 'pegaprox.db')
    dbmod.KEY_FILE = os.path.join(tmp, '.pegaprox.key')
    # get_db() caches in the module global `_db`; PegaProxDB is also a per-class
    # singleton via `_instance`. BOTH must be cleared or get_db() hands back a
    # connection to the previous test's (now-deleted) DB file.
    dbmod._db = None
    dbmod.PegaProxDB._instance = None

    database = dbmod.get_db()
    _reset_rbac_caches()  # start each test with empty process-global caches
    try:
        yield database
    finally:
        try:
            if getattr(database, '_conn', None) is not None:
                database._conn.close()
        except Exception:
            pass
        dbmod._db = None
        dbmod.PegaProxDB._instance = None
        dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE = _orig
        shutil.rmtree(tmp, ignore_errors=True)
        _reset_rbac_caches()


def _reset_rbac_caches():
    """rbac.py caches tenants / custom-roles / VM-ACLs / pool-membership at module
    scope (lazy-loaded and pinned). Without resetting them, the first test to touch
    each cache pins that test's temp-DB view for the rest of the session and later
    tests read stale authorization data. Clear them all so every test lazily
    reloads from its own throwaway DB."""
    try:
        import pegaprox.utils.rbac as rbac
        rbac.tenants_db = {}
        rbac._custom_roles_cache = None
        rbac._vm_acls_cache = None
        with rbac._pool_cache_lock:
            rbac._pool_membership_cache.clear()
    except Exception:
        pass


def _seed_user(db, username, role='user', tenant_id=DEFAULT_TENANT, enabled=True,
               portal_only=False, permissions=None, denied=None, tenant_permissions=None):
    db.save_user(username, {
        'password_salt': 'x',
        'password_hash': 'x',
        'role': role,
        'tenant_id': tenant_id,
        'enabled': enabled,
        'portal_only': portal_only,
        'permissions': permissions or [],
        'denied_permissions': denied or [],
        'tenant_permissions': tenant_permissions or {},
    })
    # Return the same shape the app hands to rbac. build_authz_user() always sets
    # user['username'] (auth.py:322); get_user() alone does not, so mirror it here
    # or rbac's `username in allowed_users` ACL check would never match.
    u = db.get_user(username)
    u['username'] = username
    return u


def _seed_tenant(db, tenant_id, clusters):
    db.save_tenant(tenant_id, {'name': tenant_id, 'clusters': list(clusters)})


def _seed_vm_acl(db, cluster_id, vmid, users, inherit_role=True, permissions=None):
    db.save_vm_acl(cluster_id, str(vmid), {
        'users': list(users),
        'inherit_role': inherit_role,
        'permissions': permissions or [],
    })


def _seed_pool_perm(db, cluster_id, pool_id, subject_id, permissions, subject_type='user'):
    db.save_pool_permission(cluster_id, pool_id, subject_type, subject_id, list(permissions))


@pytest.fixture
def seed(db):
    """Convenience seeders bound to the per-test throwaway DB."""
    ns = types.SimpleNamespace()
    ns.db = db
    ns.user = lambda username, **kw: _seed_user(db, username, **kw)
    ns.tenant = lambda tid, clusters=(): _seed_tenant(db, tid, clusters)
    ns.vm_acl = lambda cluster_id, vmid, users, **kw: _seed_vm_acl(db, cluster_id, vmid, users, **kw)
    ns.pool = lambda cluster_id, pool_id, subject_id, perms, **kw: _seed_pool_perm(
        db, cluster_id, pool_id, subject_id, perms, **kw)
    return ns
