# Full-stack integration suite for the `users` blueprint (pegaprox/api/users.py),
# focused on user management + VM-ACL management.
#
# Same harness / philosophy as tests/test_integration_smoke.py: drive the REAL
# Flask app + REAL users blueprint through HTTP, faking only the cluster manager
# where a route touches one. Every authz decision is asserted end-to-end exactly
# as a browser (or attacker) would experience it.
#
# Blueprint facts pinned here (read out of users.py):
#   * User CRUD (/api/users [GET|POST], /api/users/<u> [PUT|DELETE]) is gated
#     @require_auth(perms=['admin.users']). 'admin.users' is admin-only — it is
#     NOT in the ROLE_USER / ROLE_VIEWER permission tables — so a default-tenant
#     'user'/'viewer' is 403 (MISSING_PERMISSION), an 'admin' passes.
#   * VM-ACL CRUD (/api/clusters/<c>/vm-acls[/<vmid>]) is ALSO gated
#     ['admin.users'] and then runs check_cluster_access(). It is user-management
#     gated, not per-VM gated: an admin can set an ACL for any VM and it round-trips.
#   * A few self-service reads on the blueprint are @require_auth() only
#     (/api/user/preferences GET, /api/permissions, /api/roles/templates) — any
#     authed user, incl. a viewer, may read them.

DEFAULT = 'default'

USERS = '/api/users'
PREFS = '/api/user/preferences'
PERMS = '/api/permissions'
ROLE_TEMPLATES = '/api/roles/templates'


def _acl_route(cluster_id, vmid=None):
    base = f'/api/clusters/{cluster_id}/vm-acls'
    return base if vmid is None else f'{base}/{vmid}'


def _mgr(api):
    """A do-nothing fake manager, injected only so the '404 cluster not found'
    gates don't fire ahead of the authz decision we're actually asserting.
    None of the VM-ACL routes call a manager method on the paths tested here
    (set_vm_acl only reads cluster_managers[...].config.name when the cluster IS
    registered — we deliberately DON'T register one there, so it falls back to
    the cluster_id string and never touches a MagicMock attribute)."""
    return api.make_fake_manager(cluster_id='cluster_1')


# ===========================================================================
# unauthenticated  -> 401 everywhere
# ===========================================================================

def test_anon_list_users_401(api, seed):
    resp = api.anon().get(USERS)
    assert resp.status_code == 401


def test_anon_get_vm_acl_401(api, seed):
    api.set_manager('cluster_1', _mgr(api))
    resp = api.anon().get(_acl_route('cluster_1', 100))
    assert resp.status_code == 401


# ===========================================================================
# USER MANAGEMENT — deny paths (non-admin lacks admin.users -> 403)
# ===========================================================================

def test_viewer_cannot_list_users_403(api, seed):
    viewer = seed.user('vic', role='viewer', tenant_id=DEFAULT)
    resp = api.as_user(viewer).get(USERS)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body.get('required') == 'admin.users'


def test_user_cannot_create_user_403(api, seed):
    # a plain default-tenant 'user' has broad VM perms but NOT admin.users
    ulevel = seed.user('ursula', role='user', tenant_id=DEFAULT)
    resp = api.as_user(ulevel).post(USERS, json={
        'username': 'newbie', 'password': 'Sup3rSecret!42', 'role': 'user',
    })
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # and no user was created
    from pegaprox.utils.auth import load_users
    assert 'newbie' not in load_users()


def test_user_cannot_update_user_403(api, seed):
    seed.user('target', role='user', tenant_id=DEFAULT)
    nonadmin = seed.user('nolan', role='user', tenant_id=DEFAULT)
    resp = api.as_user(nonadmin).put(f'{USERS}/target', json={'display_name': 'Hacked'})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_user_cannot_delete_user_403(api, seed):
    seed.user('victim', role='user', tenant_id=DEFAULT)
    nonadmin = seed.user('nemo', role='viewer', tenant_id=DEFAULT)
    resp = api.as_user(nonadmin).delete(f'{USERS}/victim')
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # still present
    from pegaprox.utils.auth import load_users
    assert 'victim' in load_users()


def test_tenant_scoped_admin_cannot_delete_user_in_other_tenant_403(api, seed):
    # Cross-tenant WRITE deny: a tenant-scoped delegate (custom role carrying
    # admin.users, bound to tenant_a) PASSES the admin.users perm gate, then is
    # stopped by the in-handler tenant guard (users.py:945) when the target user
    # lives in a DIFFERENT tenant. This is the write-side twin of the VM-ACL
    # cluster-level cross-tenant deny below, and it must be a 403 from the tenant
    # guard specifically — NOT the perm gate (MISSING_PERMISSION) and NOT the
    # self-delete/not-found guards (which fire earlier for other inputs).
    from pegaprox.utils.rbac import save_custom_roles, invalidate_roles_cache
    save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'tadmin': {'name': 'Tenant Admin', 'permissions': ['admin.users']}}
    }})
    invalidate_roles_cache()

    seed.tenant('tenant_a', clusters=['cluster_home'])
    delegate = seed.user('dora', role='tadmin', tenant_id='tenant_a')
    # victim lives in the DEFAULT tenant, not tenant_a
    seed.user('outsider', role='user', tenant_id=DEFAULT)

    resp = api.as_user(delegate).delete(f'{USERS}/outsider')
    assert resp.status_code == 403, resp.get_data(as_text=True)
    body = resp.get_json()
    # the tenant guard, not the perm gate: perm-gate 403 has code MISSING_PERMISSION
    # and error 'Permission denied'; the tenant guard says 'other tenants'.
    assert body.get('code') != 'MISSING_PERMISSION'
    assert 'other tenants' in body.get('error', '').lower()
    # and the target survived
    from pegaprox.utils.auth import load_users
    assert 'outsider' in load_users()


# ===========================================================================
# USER MANAGEMENT — allow paths (admin)
# ===========================================================================

def test_admin_lists_users_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.user('bob', role='user', tenant_id=DEFAULT)

    resp = api.as_user(admin).get(USERS)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list)
    names = {u['username'] for u in body}
    assert {'root', 'bob'} <= names
    # never leak password material
    for u in body:
        assert 'password_hash' not in u and 'password_salt' not in u


def test_admin_creates_user_200_and_persists(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)

    resp = api.as_user(admin).post(USERS, json={
        'username': 'carol',
        'password': 'Str0ng-Passw0rd!x',
        'role': 'user',
        'display_name': 'Carol C',
        'email': 'carol@example.com',
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['user']['username'] == 'carol'
    assert body['user']['role'] == 'user'

    # round-trip: it's really in the store now
    from pegaprox.utils.auth import load_users
    stored = load_users()
    assert 'carol' in stored
    assert stored['carol']['role'] == 'user'
    # password was hashed, not stored in the clear
    assert stored['carol'].get('password_hash')
    assert stored['carol'].get('password_hash') != 'Str0ng-Passw0rd!x'


def test_admin_create_user_duplicate_409(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.user('dave', role='user', tenant_id=DEFAULT)

    resp = api.as_user(admin).post(USERS, json={
        'username': 'dave', 'password': 'An0ther-Str0ng!pw', 'role': 'user',
    })
    assert resp.status_code == 409, resp.get_data(as_text=True)


def test_admin_updates_user_200_and_persists(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.user('erin', role='user', tenant_id=DEFAULT)

    resp = api.as_user(admin).put(f'{USERS}/erin', json={
        'display_name': 'Erin Renamed', 'email': 'erin@corp.example',
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True

    from pegaprox.utils.auth import load_users
    erin = load_users()['erin']
    assert erin['display_name'] == 'Erin Renamed'
    assert erin['email'] == 'erin@corp.example'


def test_admin_deletes_user_200_and_removed(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.user('frank', role='user', tenant_id=DEFAULT)

    resp = api.as_user(admin).delete(f'{USERS}/frank')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True

    from pegaprox.utils.auth import load_users
    assert 'frank' not in load_users()


def test_admin_cannot_delete_own_account_400(api, seed):
    # self-delete guard is inside the handler, AFTER the admin.users gate — a 400,
    # not a 403, and the admin survives.
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    resp = api.as_user(admin).delete(f'{USERS}/root')
    assert resp.status_code == 400, resp.get_data(as_text=True)
    from pegaprox.utils.auth import load_users
    assert 'root' in load_users()


# ===========================================================================
# VM-ACL MANAGEMENT — deny paths
# ===========================================================================

def test_viewer_cannot_get_vm_acl_403(api, seed):
    # gated on admin.users; a viewer lacks it -> 403 before check_cluster_access.
    viewer = seed.user('vera', role='viewer', tenant_id=DEFAULT)
    api.set_manager('cluster_1', _mgr(api))
    resp = api.as_user(viewer).get(_acl_route('cluster_1', 100))
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json().get('required') == 'admin.users'


def test_user_cannot_set_vm_acl_403(api, seed):
    # a plain 'user' (has vm.config etc.) still cannot manage ACLs (admin.users).
    ulevel = seed.user('ugo', role='user', tenant_id=DEFAULT)
    api.set_manager('cluster_1', _mgr(api))
    resp = api.as_user(ulevel).put(_acl_route('cluster_1', 100),
                                   json={'users': ['ugo'], 'permissions': ['vm.view']})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # nothing was written
    from pegaprox.utils.rbac import get_vm_acls, invalidate_vm_acls_cache
    invalidate_vm_acls_cache()
    assert '100' not in get_vm_acls().get('cluster_1', {})


def test_cross_tenant_admin_delegate_denied_at_cluster_level_403(api, seed):
    # A tenant-scoped delegate (custom role carrying admin.users, bound to tenant_a
    # which does NOT own cluster_1) passes the admin.users perm gate, then is stopped
    # by check_cluster_access() -> 403. Proves the second gate on the ACL route.
    from pegaprox.utils.rbac import save_custom_roles, invalidate_roles_cache
    save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'tadmin': {'name': 'Tenant Admin', 'permissions': ['admin.users']}}
    }})
    invalidate_roles_cache()

    seed.tenant('tenant_a', clusters=['cluster_home'])  # does NOT own cluster_1
    delegate = seed.user('delia', role='tadmin', tenant_id='tenant_a')
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(delegate).get(_acl_route('cluster_1', 100))
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert 'cluster' in (resp.get_json().get('error', '')).lower()


# ===========================================================================
# VM-ACL MANAGEMENT — allow paths (admin)
# ===========================================================================

def test_admin_get_vm_acl_for_seeded_acl_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.vm_acl('cluster_1', 100, users=['bob', 'carol'],
                inherit_role=False, permissions=['vm.view', 'vm.console'])
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(admin).get(_acl_route('cluster_1', 100))
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['vmid'] == 100
    assert body['exists'] is True
    assert set(body['users']) == {'bob', 'carol'}
    assert set(body['permissions']) == {'vm.view', 'vm.console'}
    assert body['inherit_role'] is False


def test_admin_get_vm_acl_absent_returns_exists_false(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(admin).get(_acl_route('cluster_1', 777))
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['vmid'] == 777
    assert body['exists'] is False
    assert body['users'] == []
    assert body['permissions'] == []
    # default inherit_role is True when no ACL row exists
    assert body['inherit_role'] is True


def test_admin_sets_vm_acl_and_it_round_trips(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    # deliberately NO cluster manager registered: set_vm_acl only reads
    # cluster_managers[c].config.name WHEN c is registered; absent it uses the id.
    resp = api.as_user(admin).put(_acl_route('cluster_1', 200), json={
        'users': ['carol'],
        'permissions': ['vm.view', 'vm.start'],
        'inherit_role': False,
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['success'] is True

    # read it back THROUGH THE ROUTE (a fresh GET) -> the write actually persisted
    got = api.as_user(admin).get(_acl_route('cluster_1', 200))
    assert got.status_code == 200, got.get_data(as_text=True)
    body = got.get_json()
    assert body['exists'] is True
    assert set(body['users']) == {'carol'}
    assert set(body['permissions']) == {'vm.view', 'vm.start'}
    assert body['inherit_role'] is False

    # and directly in the store for good measure (the vm_acls table persists
    # users/permissions/inherit_role — the handler's modified/modified_by stamp is
    # audit-only and is not columnised, so we don't assert on it here).
    from pegaprox.utils.rbac import get_vm_acls, invalidate_vm_acls_cache
    invalidate_vm_acls_cache()
    stored = get_vm_acls().get('cluster_1', {}).get('200', {})
    assert stored.get('users') == ['carol']
    assert stored.get('inherit_role') is False


def test_admin_set_vm_acl_invalid_permission_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    resp = api.as_user(admin).put(_acl_route('cluster_1', 201), json={
        'users': ['carol'], 'permissions': ['totally.bogus.perm'],
    })
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert 'Invalid permission' in resp.get_json().get('error', '')


def test_admin_deletes_vm_acl_round_trip(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.vm_acl('cluster_1', 300, users=['bob'], permissions=['vm.view'])

    # sanity: it's there via the route
    pre = api.as_user(admin).get(_acl_route('cluster_1', 300))
    assert pre.get_json()['exists'] is True

    resp = api.as_user(admin).delete(_acl_route('cluster_1', 300))
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['deleted'] is True

    # gone now
    post = api.as_user(admin).get(_acl_route('cluster_1', 300))
    assert post.status_code == 200
    assert post.get_json()['exists'] is False


def test_admin_lists_cluster_vm_acls_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.vm_acl('cluster_1', 100, users=['bob'], permissions=['vm.view'])
    seed.vm_acl('cluster_1', 101, users=['carol'], permissions=['vm.console'])
    api.set_manager('cluster_1', _mgr(api))

    resp = api.as_user(admin).get(_acl_route('cluster_1'))
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list)
    by_vmid = {row['vmid']: row for row in body}
    assert set(by_vmid) == {100, 101}
    assert by_vmid[100]['users'] == ['bob']
    assert by_vmid[101]['permissions'] == ['vm.console']


# ===========================================================================
# SELF-SERVICE reads (@require_auth() only — any authed user)
# ===========================================================================

def test_viewer_reads_own_preferences_200(api, seed):
    viewer = seed.user('pat', role='viewer', tenant_id=DEFAULT)
    resp = api.as_user(viewer).get(PREFS)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    # shape from get_user_preferences()
    assert 'theme' in body and 'ui_layout' in body
    assert 'default_theme' in body


def test_viewer_reads_permission_catalog_200(api, seed):
    viewer = seed.user('quinn', role='viewer', tenant_id=DEFAULT)
    resp = api.as_user(viewer).get(PERMS)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list)
    perms = {row['permission'] for row in body}
    assert 'admin.users' in perms  # the very perm the mgmt routes require is catalogued


def test_viewer_reads_role_templates_200(api, seed):
    viewer = seed.user('rae', role='viewer', tenant_id=DEFAULT)
    resp = api.as_user(viewer).get(ROLE_TEMPLATES)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert isinstance(body, list)
    for tpl in body:
        assert 'id' in tpl and 'permissions' in tpl
