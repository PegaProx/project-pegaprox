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
            # PegaProxDB keeps its live handle on a threadlocal (self._local.conn);
            # `_conn` is always None. Close the real connection so the temp DB file
            # isn't held open when we rmtree it below.
            _tlconn = getattr(getattr(database, '_local', None), 'conn', None)
            if _tlconn is not None:
                _tlconn.close()
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


# ===========================================================================
# Phase 3 — full-stack INTEGRATION harness.
#
# The RBAC tests above call user_can_access_vm() directly. That is fast but it
# skips the whole HTTP stack — the exact reason the 2026-07-12 "BOLA" framing was
# wrong (the guards behave differently once check_cluster_access + require_auth +
# the additive role-fallback all run in sequence). These fixtures drive REAL
# requests through the REAL Flask app + real blueprints, with the cluster managers
# faked out, so an authz decision is asserted end-to-end exactly as a browser (or
# an attacker) would experience it.
#
# Design:
#   * ONE session-scoped app (create_app is heavy — background greenlets, etc.),
#     built against an isolated temp DB so it NEVER touches the developer's real
#     encrypted DB (which has live clusters). save_sessions() is silenced.
#   * per-test DB isolation reuses the function-scoped `db` fixture: routes call
#     get_db() lazily, so re-pointing the db module globals per test gives each
#     test a clean DB while the app object lives on.
#   * auth uses the REAL server-side session store (create_session -> active_sessions,
#     addressed via the X-Session-ID header) — the same path production login uses.
#   * managers are faked and injected into pegaprox.globals.cluster_managers (the
#     dict every route imports by reference). The DENY path (403) fires before the
#     manager is ever touched, so deny-tests need no method stubs; allow-tests stub
#     exactly the manager method their route calls.
# ===========================================================================

from unittest.mock import MagicMock


def make_fake_manager(cluster_id='cluster_1', cluster_type='proxmox', **method_returns):
    """A stand-in cluster manager. Any attribute access works (MagicMock); the
    methods a given route calls are stubbed via kwargs, e.g.
        make_fake_manager(get_vm_config={'success': True, 'config': {...}})
    Unstubbed methods return a MagicMock — fine for deny-tests (never called),
    but an allow-test MUST stub the exact method its route invokes or the route
    will try to jsonify a MagicMock and 500 (a loud, obvious failure)."""
    m = MagicMock(name=f'FakeManager[{cluster_id}]')
    m.cluster_id = cluster_id
    m.cluster_type = cluster_type
    m.name = cluster_id
    m.online = True
    for meth, ret in method_returns.items():
        getattr(m, meth).return_value = ret
    return m


@pytest.fixture(scope='session')
def _integration_app():
    """The real Flask app, created ONCE against an isolated temp DB."""
    import pegaprox.core.db as dbmod
    import pegaprox.utils.auth as authmod

    tmp = tempfile.mkdtemp(prefix='pp_integ_app_')
    dbmod.CONFIG_DIR = tmp
    dbmod.DATABASE_FILE = os.path.join(tmp, 'pegaprox.db')
    dbmod.KEY_FILE = os.path.join(tmp, '.pegaprox.key')
    dbmod._db = None
    dbmod.PegaProxDB._instance = None

    # never persist test sessions to disk
    authmod.save_sessions = lambda *a, **k: None

    from pegaprox.app import create_app
    app = create_app()
    app.config['TESTING'] = True

    try:
        yield app
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class _ApiClient:
    """Thin wrapper over the Flask test client that bakes in the session header
    and — for state-changing verbs — the same-origin + XHR headers the CSRF gate
    requires. base_url is pinned to http://localhost so request.host == 'localhost'
    (same-origin matching)."""
    _BASE = 'http://localhost'

    def __init__(self, client, session_id=None):
        self._c = client
        self.session_id = session_id

    def _headers(self, extra, write):
        h = {}
        if self.session_id:
            h['X-Session-ID'] = self.session_id
        if write:
            h['X-Requested-With'] = 'XMLHttpRequest'
            h['Origin'] = self._BASE
        if extra:
            h.update(extra)
        return h

    def _call(self, method, path, write, headers=None, **kw):
        fn = getattr(self._c, method)
        return fn(path, headers=self._headers(headers, write), base_url=self._BASE, **kw)

    def get(self, path, **kw):    return self._call('get', path, False, **kw)
    def delete(self, path, **kw): return self._call('delete', path, True, **kw)
    def post(self, path, **kw):   return self._call('post', path, True, **kw)
    def put(self, path, **kw):    return self._call('put', path, True, **kw)
    def patch(self, path, **kw):  return self._call('patch', path, True, **kw)


@pytest.fixture
def api(_integration_app, db):
    """Full-stack test harness. `db` gives a fresh per-test DB; this clears the
    process-global session + manager state so tests can't leak into each other."""
    import pegaprox.utils.auth as authmod
    import pegaprox.globals as ppglobals

    with authmod.sessions_lock:
        authmod.active_sessions.clear()
    ppglobals.cluster_managers.clear()

    client = _integration_app.test_client()

    def as_user(user):
        """Mint a real server-side session for a seeded user dict and return a
        client that authenticates as them."""
        from pegaprox.utils.auth import create_session
        with _integration_app.test_request_context('/', base_url=_ApiClient._BASE):
            sid = create_session(user['username'], user['role'])
        return _ApiClient(client, sid)

    def set_manager(cluster_id, fake):
        ppglobals.cluster_managers[cluster_id] = fake
        return fake

    ns = types.SimpleNamespace(
        app=_integration_app,
        as_user=as_user,
        anon=lambda: _ApiClient(client, None),
        set_manager=set_manager,
        make_fake_manager=make_fake_manager,
    )
    try:
        yield ns
    finally:
        with authmod.sessions_lock:
            authmod.active_sessions.clear()
        ppglobals.cluster_managers.clear()


@pytest.fixture
def make_fake_manager_fixture():
    """Expose the factory as a fixture too, for tests that prefer injection."""
    return make_fake_manager
