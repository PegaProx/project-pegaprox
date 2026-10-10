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
import threading
import types
import tempfile
import shutil

import pytest


def _poll(done):
    import gevent
    while not done():
        gevent.sleep(0.02)
    return True


class _PolledFlag:
    """What xdist's worker queue waits on, without a wake-up across threads."""

    def __init__(self):
        self._set = False

    def set(self):
        self._set = True

    def clear(self):
        self._set = False

    def wait(self, timeout=None):
        return _poll(lambda: self._set)


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'guard_refusals: the test makes the transport guard refuse a write that '
        'carries no confirmed lease on purpose (#625; anywhere else that fails the test)')
    # Under pytest-xdist the worker's main thread waits on execnet's receiver, and that
    # receiver is a real thread: it was started before the patch above. What the two
    # share is locked and signalled with gevent's primitives from then on, and a
    # release from the other thread now and then never wakes the worker - it sits there
    # for good, or the idle hub ends the wait with LoopExit. So the three waits of the
    # main thread poll instead: for the next test, for the shutdown, and for the
    # receiver to end. The queue's lock is a real one, held for a few instructions.
    if not hasattr(config, 'workerinput'):
        return
    import _thread
    for plugin in config.pluginmanager.get_plugins():
        queue = getattr(plugin, 'torun', None)
        if queue is None or not hasattr(queue, '_has_items_event'):
            continue
        queue._lock = _thread.RLock()
        queue._has_items_event = _PolledFlag()
        gateway = plugin.channel.gateway
        ready = getattr(gateway._execpool, '_primary_thread_task_ready', None)
        if ready is not None:
            ready.wait = lambda timeout=None, ev=ready: _poll(ev.is_set)
        receivers = gateway._receivepool
        receivers.waitall = lambda timeout=None, pool=receivers: _poll(lambda: not pool.active_count())


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


def unconfirmed_writes():
    """The writes the transport guard refused in this test for want of a confirmed lease
    in a background context (#625, design 5.3), however the code around them took it."""
    from pegaprox.core import ha
    return sorted(action for action, why in ha._guard_said
                  if why in (ha.GUARD_NO_TOKEN, ha.GUARD_RAN_OUT))


@pytest.fixture(autouse=True)
def _ha_state_out_of_the_checkout(tmp_path, monkeypatch, request):
    """A checkout whose config/ha_state.json says standby would turn every write in
    the suite into a 409, and a snapshot applied in a test would write the checkout's
    known_hosts, branding and plugin configs. Every test gets its own throwaway set;
    AES_KEY_FILE too, because a .pre-ha backup next to it marks a joined instance."""
    from pegaprox.core import ha
    ha_dir = tmp_path / 'ha'
    ha_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(ha, 'STATE_FILE', str(ha_dir / 'ha_state.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(ha_dir / '.pegaprox_aes256.key'))
    monkeypatch.setattr(ha, 'KNOWN_HOSTS_FILE', str(ha_dir / '.ssh_known_hosts'))
    monkeypatch.setattr(ha, 'BRANDING_DIR', str(ha_dir / 'branding'))
    monkeypatch.setattr(ha, 'PLUGINS_DIR', str(ha_dir / 'plugins'))
    # what a sync did not carry over is kept there; the change journal waits in memory,
    # and so does what the tick last saw
    monkeypatch.setattr(ha, 'ORPHANS_DIR', str(ha_dir / 'ha_orphans'))
    monkeypatch.setattr(ha, '_journal', {'pending': [], 'dropped': 0, 'last_id': None,
                                         'filled_to': 0, 'due': False})
    # its timer is a second one next to the note's, which the group tests count
    monkeypatch.setattr(ha, '_journal_later', lambda: None)
    monkeypatch.setattr(ha, '_tick', {'seen': None, 'checked': None, 'schema': None})
    monkeypatch.setattr(ha, '_read_look', {'checked': None, 'schema': None})
    # a process that has synced before: its first sync would read the rows whatever the
    # change mark says, and which test runs first in a worker must not matter
    monkeypatch.setattr(ha, '_mark_checked', True)
    monkeypatch.setattr(ha, '_orphans', {'count': None, 'over_said': False, 'not_kept': None})
    # an applied snapshot reloads the IP allow list from that test's database into
    # module globals; without this a later test in the run meets someone else's list
    import pegaprox.api.settings as settings_api
    monkeypatch.setattr(settings_api, '_ip_whitelist_enabled', False)
    monkeypatch.setattr(settings_api, '_ip_whitelist', set())
    monkeypatch.setattr(settings_api, '_ip_blacklist', set())
    # The certificate in the checkout's config/ssl (a dev instance's) went into every
    # pairing code a test made, so the pins in the member records depended on the
    # machine: green in CI, red next to a running instance. A test that wants a pin
    # sets one.
    import pegaprox.api.auto_install as auto_install
    monkeypatch.setattr(auto_install, 'self_signed_fingerprint', lambda: '')
    # A signed call from before the process started is refused (the nonces seen until
    # then are gone). The test process started whenever the run did, so every test
    # counts as a process that has run for longer than the signature window (lease
    # time 0 is the boot of the host).
    monkeypatch.setattr(ha, '_PROCESS_STARTED', 0)
    # a standby's note that its active did not answer lives as long as the process
    monkeypatch.setattr(ha, '_silent_source', {'id': None})
    # A timer of core/ha.py (the active's note to its members after a write, a standby's
    # reload once a change has settled) fires seconds later on a thread of its own, in
    # whatever state file a later test holds by then. None starts here; a test that
    # wants one replaces ha._later and runs what it was handed.
    monkeypatch.setattr(ha, '_later', lambda delay, fn, name: None)
    monkeypatch.setattr(ha, '_nudge', {'due': False, 'last': None})
    monkeypatch.setattr(ha, '_run', ha._fresh_run())
    # Automatic failover: what runs a lease lives as long as the process, one per
    # instance id. Nothing of it runs on its own in a test - no loop, no watchdog, no
    # call in the background: the calls a node wants sent stay in its queue, and a test
    # that wants them delivers them by hand (tests/test_ha_auto.py).
    monkeypatch.setattr(ha, '_rts', {})
    monkeypatch.setattr(ha, 'lease_start', lambda: False)
    monkeypatch.setattr(ha, '_lease_dispatch', lambda rt: None)
    monkeypatch.setattr(ha, '_lease_spawn', lambda fn, name: None)
    # the zone of the machine the suite runs on would go into every group a test forms
    monkeypatch.setattr(ha, '_local_zone', {'name': ''})
    # what the transport guard holds per thread (a confirmed lease, a read, a job) and
    # what it said, from a test before: the tests share their greenlet (S4)
    monkeypatch.setattr(ha, '_guard_tls', threading.local())
    monkeypatch.setattr(ha, '_guard_said', set())
    monkeypatch.setattr(ha, '_recovery_live', set())
    monkeypatch.setattr(ha, '_missed_said', {})
    ha.reset_for_tests()
    yield
    # in a test, a background write without a confirmed lease is a failure even where
    # a broad except swallowed the refusal (design 5.3)
    unconfirmed = unconfirmed_writes()
    ha.reset_for_tests()
    if unconfirmed and request.node.get_closest_marker('guard_refusals') is None:
        pytest.fail('the transport guard refused writes that no step confirmed: '
                    f'{unconfirmed[:5]} - confirm the step before it (ha.confirm_step), run '
                    'the job through ha.as_job or carry the token into the fan-out (ha.carry); '
                    'mark the test guard_refusals where the refusal is what it tests')


@pytest.fixture(autouse=True)
def _node_history_forgotten():
    """What core/node_history.py knows of each node lives as long as the process, and the
    next test's cluster_1 is another cluster with another database."""
    from pegaprox.core import node_history
    node_history.forget()
    yield
    node_history.forget()


def _reset_api_rate_window():
    """Forget every client the API rate limiter has seen. Shared process state, and the
    whole harness looks like one client to it."""
    try:
        import pegaprox.globals as ppglobals
        ppglobals.api_rate_window.reset()
    except Exception:
        pass


def _reset_guest_index():
    """The guest search index keeps what every config read handed it, by cluster id, and
    the next test's cluster_1 is another cluster."""
    try:
        from pegaprox.background import guest_index
        guest_index.clear()
    except Exception:
        pass


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
        # the quota's holds and the storage contents it read are process state too
        rbac._quota_holds.clear()
        rbac._disk_alloc_cache.clear()
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

    # never persist test sessions to disk (a test that checks what would be saved
    # calls the real one with get_db patched)
    authmod._real_save_sessions = authmod.save_sessions
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
    # MK Sep 2026 - cluster_managers was the only manager registry being reset, so a fake
    # PBS or ESXi manager left behind by an earlier test stayed visible to every test after
    # it. That is invisible until a test touches a route that walks one of those registries:
    # check_cluster_updates does `pbs_results[pmgr.name or pid]`, and `pmgr.name` on a
    # leftover MagicMock is a MagicMock, so jsonify died with "keys must be str ... not
    # MagicMock" in a full-suite run while the same test passed on its own.
    for _registry in ('pbs_managers', 'vmware_managers'):
        getattr(ppglobals, _registry, {}).clear()
    # MK Sep 2026 — the API rate limiter is a process-global sliding window keyed by client
    # IP (1200 requests / 60s), and every request in this harness arrives from the same one.
    # Nothing reset it between tests, so a long integration run could put more than the
    # budget into a single 60s window and everything after that failed with 429s instead of
    # whatever it was actually asserting. That is what took the Testing CI red on ae8674d
    # (run 35697303667) while the same tree was green on a slower machine here. reset() is
    # already the method the unlock endpoints use.
    _reset_api_rate_window()
    _reset_guest_index()

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
        for _registry in ('pbs_managers', 'vmware_managers'):
            getattr(ppglobals, _registry, {}).clear()
        _reset_api_rate_window()
        _reset_guest_index()


@pytest.fixture
def make_fake_manager_fixture():
    """Expose the factory as a fixture too, for tests that prefer injection."""
    return make_fake_manager
