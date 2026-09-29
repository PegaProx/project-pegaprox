"""Regression tests for the five MK #950 review fixes (Sep 2026).

Each test measures the property MK flagged, not the presence of a guard:
  1. the backfill must not auto-grant cross-tenant on duplicate role names
  2. a delegate cannot grant permissions they do not hold
  3. a non-admin cannot grant a tenant they are not a member of
  4. a token-capped caller must not inherit the OWNER's admin shortcut
  5. a tenant-pinned grant goes dormant when the membership is revoked
  6. role grants are read once per request, not once per VM (scale)
"""
import pytest

import pegaprox.core.db as dbmod
import pegaprox.utils.rbac as rbac


def _grant_rows(db, username):
    cur = db.conn.cursor()
    cur.execute('SELECT role_name, tenant_id FROM user_roles WHERE username = ?', (username,))
    return sorted((r[0], r[1]) for r in cur.fetchall())


def _memberships(db, username):
    cur = db.conn.cursor()
    cur.execute('SELECT tenant_id FROM user_tenants WHERE username = ?', (username,))
    return sorted(r[0] for r in cur.fetchall())


# ===========================================================================
# 1. Backfill uniqueness (MK's bob/operator repro)
# ===========================================================================

def test_backfill_skips_ambiguous_primary_roles(db, seed):
    """Two tenants both defining 'operator' + a tenant_a user whose PRIMARY
    role is 'operator' -> only the own-tenant junction row, never the
    cross-tenant twin nobody granted."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    seed.tenant('tenant_b', clusters=('cluster_2',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'operator': {'permissions': ['vm.view']}},
        'tenant_b': {'operator': {'permissions': ['vm.view']}}}})
    rbac._custom_roles_cache = None
    seed.user('bob', role='operator', tenant_id='tenant_a')

    # The backfill lives in _init_db(); re-running it on the live connection
    # re-executes the (now guarded) INSERT..SELECT directly.
    db._init_db()

    rows = _grant_rows(db, 'bob')
    assert ('operator', 'tenant_a') in rows, 'own-tenant grant must exist'
    assert ('operator', 'tenant_b') not in rows, \
        'cross-tenant auto-grant fired on a duplicate role name'


def test_backfill_still_pins_unambiguous_primary_roles(db, seed):
    """A role name defined by exactly one tenant still backfills with its
    defining tenant pinned (legacy behavior preserved for the common case)."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'auditor': {'permissions': ['vm.view']}}}})
    rbac._custom_roles_cache = None
    seed.user('mona', role='auditor', tenant_id='tenant_a')

    db._init_db()

    rows = _grant_rows(db, 'mona')
    assert ('auditor', 'tenant_a') in rows, 'unambiguous backfill must survive the guard'


# ===========================================================================
# 2. No granting permissions you do not hold (roles_grant)
# ===========================================================================

def test_delegate_cannot_grant_permissions_they_do_not_hold(api, db, seed):
    """authz gap 1: a viewer delegate holding only admin.users must not be
    able to hand out a role carrying vm.console/node.power."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'super_ops': {'permissions': ['vm.console', 'node.power']}}}})
    rbac._custom_roles_cache = None
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a',
                      permissions=['admin.users'])
    seed.user('bob', role='viewer', tenant_id='tenant_a')

    r = api.as_user(alice).put('/api/users/bob/roles', json={'role': 'super_ops'})
    assert r.status_code == 403, f'delegate granted perms they do not hold ({r.status_code})'
    assert b'Cannot grant permissions you do not hold' in r.data
    assert _grant_rows(db, 'bob') == [], 'the grant must not be written'


def test_admin_still_grants_across_permission_sets(api, db, seed):
    """The gap-1 check is a delegate rule: a real global admin without
    vm.console must still be able to grant a role that carries it."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'super_ops': {'permissions': ['vm.console', 'node.power']}}}})
    rbac._custom_roles_cache = None
    admin = seed.user('root_admin', role='admin', tenant_id='tenant_a')
    seed.user('bob', role='viewer', tenant_id='tenant_a')

    r = api.as_user(admin).put('/api/users/bob/roles', json={'role': 'super_ops'})
    assert r.status_code == 200, f'admin grant path must not be closed ({r.status_code})'
    assert ('super_ops', 'tenant_a') in _grant_rows(db, 'bob')


# ===========================================================================
# 3. No granting a tenant you do not hold (tenants_grant_d6)
# ===========================================================================

def test_delegate_cannot_grant_tenant_they_are_not_member_of(api, db, seed):
    """authz gap 2: target shares the caller's home tenant (so the pre-existing
    shared-tenant check passes) but the requested tenant is one the caller
    does not hold — that grant must be refused, not inserted."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    seed.tenant('tenant_b', clusters=('cluster_2',))
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a',
                      permissions=['admin.users'])
    seed.user('bob', role='viewer', tenant_id='tenant_a')

    r = api.as_user(alice).put('/api/users/bob/tenants', json={'tenant_id': 'tenant_b'})
    assert r.status_code == 403, f'cross-tenant membership minted ({r.status_code})'
    assert b'not a member of' in r.data
    assert 'tenant_b' not in _memberships(db, 'bob')


def test_member_delegate_still_grants_owned_tenant(api, db, seed):
    """The gap-2 rule is not a blanket freeze: a delegate who IS a member of
    tenant_b can still share it with a same-home colleague."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    seed.tenant('tenant_b', clusters=('cluster_2',))
    alice = seed.user('alice', role='viewer', tenant_id='tenant_a',
                      permissions=['admin.users'])
    seed.user('bob', role='viewer', tenant_id='tenant_a')

    cur = db.conn.cursor()
    cur.execute("INSERT INTO user_tenants (username, tenant_id, granted_at, granted_by) "
                "VALUES ('alice', 'tenant_b', '2026-09-29', 'test')")
    db.conn.commit()

    r = api.as_user(alice).put('/api/users/bob/tenants', json={'tenant_id': 'tenant_b'})
    assert r.status_code == 200, f'member delegate refused ({r.status_code}): {r.data[:120]}'
    assert 'tenant_b' in _memberships(db, 'bob')


# ===========================================================================
# 4. Token-capped caller must not ride the OWNER's admin shortcut
# ===========================================================================

def test_token_capped_caller_does_not_inherit_owner_admin(api, db, seed):
    """authz gap 3: a viewer-capped token owned by a global admin must take
    the scoped path. The role here carries only vm.view (so gap 1 passes for
    this caller) and the target sits in ANOTHER tenant (so the scoped path
    must refuse on containment — the owner shortcut would have granted)."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    seed.tenant('tenant_b', clusters=('cluster_2',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_b': {'weak_ops': {'permissions': ['vm.view']}}}})
    rbac._custom_roles_cache = None
    owner = seed.user('token_owner', role='admin', tenant_id='tenant_a')
    seed.user('bob', role='viewer', tenant_id='tenant_b')

    from pegaprox.utils.auth import create_session
    import pegaprox.utils.auth as authmod
    with api.app.test_request_context('/', base_url='http://localhost'):
        sid = create_session(owner['username'], owner['role'])
    with authmod.sessions_lock:
        sess = authmod.active_sessions[sid]
        sess['api_token'] = 'test-token'
        sess['role'] = 'viewer'

    client = api.app.test_client()
    r = client.put('/api/users/bob/roles', json={'role': 'weak_ops'},
                   headers={'X-Session-ID': sid,
                            'X-Requested-With': 'XMLHttpRequest',
                            'Origin': 'http://localhost'},
                   base_url='http://localhost')
    assert r.status_code != 200, \
        f'token-capped caller rode the owner shortcut ({r.status_code})'
    assert ('weak_ops', 'tenant_b') not in _grant_rows(db, 'bob')


# ===========================================================================
# 5. Revoke dormancy
# ===========================================================================

def test_tenant_pinned_grant_goes_dormant_on_membership_revoke(db, seed):
    """_effective_tenant_ids must ignore a tenant-pinned grant whose tenant
    membership is gone (the docstring always promised dormant, the loop
    never implemented it)."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    seed.tenant('tenant_b', clusters=('cluster_2',))
    carol = seed.user('carol', role='viewer', tenant_id='tenant_a')

    cur = db.conn.cursor()
    cur.execute("INSERT INTO user_tenants (username, tenant_id, granted_at, granted_by) "
                "VALUES ('carol', 'tenant_b', '2026-09-29', 'test')")
    cur.execute("INSERT INTO user_roles (username, role_name, tenant_id, granted_at, granted_by) "
                "VALUES ('carol', 'some_role', 'tenant_b', '2026-09-29', 'test')")
    db.conn.commit()

    before = rbac._effective_tenant_ids(carol)
    assert 'tenant_b' in before, 'precondition: live membership grants visibility'

    cur.execute("DELETE FROM user_tenants WHERE username = 'carol' AND tenant_id = 'tenant_b'")
    db.conn.commit()

    after = rbac._effective_tenant_ids(carol)
    assert 'tenant_b' not in after, \
        'dormant grant still widened cluster visibility after revoke'


def test_legacy_empty_tenant_grant_still_resolves_through_role(db, seed):
    """Migration rows with tenant_id='' keep resolving through the role name
    (they only ever exist for names defined in exactly one tenant)."""
    seed.tenant('tenant_a', clusters=('cluster_1',))
    rbac.save_custom_roles({'global': {}, 'tenants': {
        'tenant_a': {'solo_role': {'permissions': ['vm.view']}}}})
    rbac._custom_roles_cache = None
    # dan sits in the DEFAULT tenant — exactly the caller _tenant_defining_role
    # remaps, so the legacy row must carry tenant_a in.
    dan = seed.user('dan', role='viewer', tenant_id='default')

    cur = db.conn.cursor()
    cur.execute("INSERT INTO user_tenants (username, tenant_id, granted_at, granted_by) "
                "VALUES ('dan', 'default', '2026-09-29', 'test')")
    cur.execute("INSERT INTO user_roles (username, role_name, tenant_id, granted_at, granted_by) "
                "VALUES ('dan', 'solo_role', '', '2026-09-29', 'test')")
    db.conn.commit()

    tids = rbac._effective_tenant_ids(dan)
    assert 'tenant_a' in tids, 'legacy empty-tenant grant stopped resolving through the role'


# ===========================================================================
# 6. Scale: one junction read per request, not per VM
# ===========================================================================

def test_grant_lookup_memoised_within_request(api, monkeypatch):
    """The per-VM loop must hit the junction read once per request."""
    calls = {'n': 0}
    real = rbac._user_role_grants_read

    def counting(username):
        calls['n'] += 1
        return real(username)

    monkeypatch.setattr(rbac, '_user_role_grants_read', counting)

    from flask import has_request_context
    with api.app.test_request_context('/'):
        assert has_request_context()
        rbac.get_user_role_grants('someone')
        rbac.get_user_role_grants('someone')
        rbac.get_user_role_grants('someone')
        assert calls['n'] == 1, 'junction read ran more than once per request'

        rbac.invalidate_user_grants_memo('someone')
        rbac.get_user_role_grants('someone')
        assert calls['n'] == 2, 'invalidation did not force a fresh read'

    # outside request context: straight through, no memo
    calls['n'] = 0
    rbac.get_user_role_grants('someone')
    assert calls['n'] == 1
