"""Tenant scope and delegated administration: the low findings of October.

  * A tenant role named in the override of the tenant an account lives in gave it that
    tenant's permissions on the default tenant's scope: every cluster, when the default
    tenant has no list (#992).
  * A role nobody defines (deleted while held, or a role store that did not load) fell
    back to the default tenant's scope as well (#1061).
  * The cluster-group routes read a default-tenant account on another tenant's role as
    unscoped, so with admin.groups it edited every tenant's groups and the global ones
    (#1008).
  * A VM ACL's inherit_role was weighed by its truthiness and stored by its string, so
    inherit_role=[] passed the ceiling as false and was saved as true (#1085).
  * A read-only grant on a pool was enough to take a guest out of it.
  * A tenant delegate holding security.lockout.manage expired every tenant's passwords and
    cleared every tenant's user lockouts.
  * The OIDC connection test followed redirects of the JWKS URL past the outbound URL guard.
  * A tenant chargeback listed every guest on the tenant's clusters to a delegate confined
    to some of them.
  * An unreadable tenant table read as "no VMID range" and let any VMID through.

NS Oct 2026
"""
import json
import time
from datetime import datetime
from unittest.mock import MagicMock

import pytest

import pegaprox.api.costs as costs
import pegaprox.api.users as usersapi
import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
from pegaprox.utils.auth import apply_token_role

X_PERMS = ['vm.view', 'cluster.view']


def _role(db, name, perms, tenant_id=''):
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES (?, ?, ?, ?, '2026-01-01T00:00:00')",
                    (name, json.dumps(perms), name, tenant_id))
    db.conn.commit()
    rbac.invalidate_roles_cache()


@pytest.fixture
def estate(db, seed):
    """The default tenant has no cluster list (every cluster). tenant_x owns c_x and
    defines x-ops, g-ops is a global role."""
    seed.tenant(rbac.DEFAULT_TENANT_ID, [])
    seed.tenant('tenant_x', ['c_x'])
    seed.tenant('tenant_y', ['c_y'])
    _role(db, 'x-ops', X_PERMS, 'tenant_x')
    _role(db, 'g-ops', X_PERMS)
    rbac.invalidate_tenants_cache()
    return seed


# --- #992: the home override's tenant role picks the clusters ----------------------------

def test_a_tenant_role_in_the_home_override_takes_that_tenants_clusters(estate):
    dora = estate.user('dora', role='user', tenant_permissions={'default': {'role': 'x-ops'}})
    assert sorted(rbac.get_user_permissions(dora)) == sorted(X_PERMS)

    assert rbac.get_user_clusters(dora, include_pools=False) == ['c_x'], \
        'tenant_x permissions on every cluster'


def test_a_default_tenant_account_without_an_override_keeps_every_cluster(estate):
    assert rbac.get_user_clusters(estate.user('plain', role='user')) is None


def test_an_override_naming_a_builtin_leaves_the_own_role_to_decide(estate):
    assert rbac.get_user_clusters(estate.user(
        'u1', role='user', tenant_permissions={'default': {'role': 'viewer'}})) is None
    assert rbac.get_user_clusters(estate.user(
        'u2', role='x-ops', tenant_permissions={'default': {'role': 'viewer'}}),
        include_pools=False) == ['c_x']


def test_a_lowered_admin_still_takes_the_overrides_tenant(estate):
    alex = estate.user('alex', role='admin', tenant_permissions={'default': {'role': 'x-ops'}})
    assert rbac.get_user_clusters(alex, include_pools=False) == ['c_x']


def test_a_token_of_such_an_account_stays_inside_its_clusters(estate):
    dora = estate.user('dora', role='user', tenant_permissions={'default': {'role': 'x-ops'}})
    token = apply_token_role(dora, 'viewer')
    assert set(rbac.get_user_clusters(token, include_pools=False) or ['*']) <= {'c_x'}


# --- #1061: a role nobody defines has no tenant -------------------------------------------

def test_a_role_nobody_defines_reaches_no_cluster(estate):
    ghost = estate.user('ghost', role='deleted-role')
    assert rbac.get_user_permissions(ghost) == []
    assert rbac.get_user_clusters(ghost) == [], 'zero permissions, every cluster in view'


def test_an_unreadable_role_store_reaches_no_cluster_either(estate, monkeypatch):
    gina = estate.user('gina', role='g-ops')
    monkeypatch.setattr(rbac, 'get_custom_roles',
                        lambda: rbac._Snapshot({'global': {}, 'tenants': {}}, unavailable=True))
    assert rbac.get_user_clusters(gina) == []


def test_a_global_role_still_takes_the_default_tenant(estate):
    assert rbac.get_user_clusters(estate.user('gina', role='g-ops')) is None


def test_a_role_in_the_default_tenants_own_table_still_resolves(estate, db):
    _role(db, 'd-ops', X_PERMS, rbac.DEFAULT_TENANT_ID)
    assert rbac.get_user_clusters(estate.user('dan', role='d-ops')) is None


# --- #1008: cluster groups follow the tenant the role puts an account in ------------------

@pytest.fixture
def groups(api, estate, db):
    _role(db, 'x-grp', ['admin.groups', 'cluster.view'], 'tenant_x')
    for gid, tid in (('grp_x', 'tenant_x'), ('grp_y', 'tenant_y'), ('grp_global', None)):
        db.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES (?, ?, ?)",
                   (gid, gid, tid))
    db.conn.commit()
    return estate


def _rename(client, gid):
    return client.put(f'/api/cluster-groups/{gid}', json={'name': 'renamed'}).status_code


def test_a_default_tenant_account_on_a_tenant_role_edits_no_foreign_group(api, groups):
    c = api.as_user(groups.user('xena', role='x-grp'))

    assert _rename(c, 'grp_global') == 404, 'edited a global group'
    assert _rename(c, 'grp_y') == 404, "edited another tenant's group"
    assert {g['id'] for g in c.get('/api/cluster-groups').get_json()} <= {'grp_x', 'grp_global'}


def test_it_still_edits_its_own_tenants_group(api, groups):
    c = api.as_user(groups.user('xena', role='x-grp'))
    assert _rename(c, 'grp_x') == 200


def test_a_default_tenant_operator_on_a_builtin_role_is_unscoped_as_before(api, groups):
    c = api.as_user(groups.user('dee', role='user', permissions=['admin.groups']))
    assert _rename(c, 'grp_global') == 200
    assert {'grp_x', 'grp_y', 'grp_global'} <= {g['id'] for g in c.get('/api/cluster-groups').get_json()}


def test_a_member_of_the_tenant_itself_is_unchanged(api, groups):
    c = api.as_user(groups.user('xavier', role='x-grp', tenant_id='tenant_x'))
    assert _rename(c, 'grp_x') == 200
    assert _rename(c, 'grp_global') == 404


# --- #1085: inherit_role is a boolean, users and permissions are lists ---------------------

CL = 'cluster_1'


@pytest.fixture
def acl_estate(api, seed, db):
    seed.tenant('t', [CL])
    _role(db, 't-acl', ['admin.users', 'vm.view', 'vm.config', 'cluster.view'], 't')
    rbac.invalidate_tenants_cache()
    seed.user('eve', role='viewer', tenant_id='t')
    return {'dee': api.as_user(seed.user('dee', role='t-acl', tenant_id='t')),
            'root': api.as_user(seed.user('root', role='admin'))}


def _put_acl(client, **body):
    return client.put(f'/api/clusters/{CL}/vm-acls/100', json={'users': ['eve'], **body})


def test_a_list_for_inherit_role_is_refused(acl_estate, db):
    """Weighed as false against ['vm.view'], stored as true: the whole inherited set."""
    r = _put_acl(acl_estate['dee'], permissions=['vm.view'], inherit_role=[])

    assert r.status_code == 400, r.get_json()
    assert str(100) not in (db.get_all_vm_acls().get(CL) or {}), 'the row was stored'


def test_a_string_of_users_is_refused(acl_estate, db):
    r = _put_acl(acl_estate['root'], permissions=['vm.view'], inherit_role=False,
                 users='alice-and-bob')
    assert r.status_code == 400


def test_a_boolean_inherit_role_works_as_before(acl_estate, db):
    assert _put_acl(acl_estate['dee'], permissions=['vm.view'], inherit_role=False).status_code == 200
    assert db.get_all_vm_acls()[CL]['100']['inherit_role'] is False
    # the inherited set is beyond what the delegate holds
    assert _put_acl(acl_estate['dee'], permissions=[], inherit_role=True).status_code == 403
    assert _put_acl(acl_estate['root'], permissions=[], inherit_role=True).status_code == 200


# --- removing a guest from its pool needs management of the guest -------------------------

VMID = 150


def _membership(cluster_id, mapping):
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': {f'{vmid}:{vtype}': pool for vmid, (vtype, pool) in mapping.items()},
            'timestamp': time.time(), 'refreshing': False,
        }


@pytest.fixture
def pooled(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t_elsewhere', [])
    mgr = api.make_fake_manager(CL)
    mgr._api_put.return_value = MagicMock(status_code=200, text='')
    api.set_manager(CL, mgr)
    _membership(CL, {VMID: ('lxc', 'pool_mine')})
    return seed


def _remove(client):
    return client.delete(f'/api/clusters/{CL}/pools/pool_mine/members/{VMID}')


def test_a_read_only_grant_on_the_pool_cannot_take_a_guest_out(api, pooled):
    pooled.pool(CL, 'pool_mine', 'robin', ['pool.view', 'vm.view'])
    robin = api.as_user(pooled.user('robin', role='user', tenant_id='t_elsewhere',
                                    permissions=['pool.assign']))
    r = _remove(robin)
    assert r.status_code == 403, r.get_json()
    assert 'removed from its pool' in r.get_json()['error']


def test_a_managing_grant_still_takes_its_container_out(api, pooled):
    pooled.pool(CL, 'pool_mine', 'sam', ['pool.view', 'vm.view', 'vm.config'])
    sam = api.as_user(pooled.user('sam', role='user', tenant_id='t_elsewhere',
                                  permissions=['pool.assign']))
    r = _remove(sam)
    assert r.status_code == 200, r.get_json()


def test_an_admin_still_takes_a_guest_out(api, pooled):
    assert _remove(api.as_user(pooled.user('root', role='admin'))).status_code == 200


# --- the lockout and password expiry bulk routes stay in the delegate's tenant -------------

@pytest.fixture
def lockout_estate(api, seed):
    seed.tenant('acme', [])
    seed.tenant('globex', [])
    seed.user('alma', role='user', tenant_id='acme')
    seed.user('boss', role='admin', tenant_id='acme')
    seed.user('gus', role='user', tenant_id='globex')
    seed.user('root', role='admin')
    helen = seed.user('helen', role='user', tenant_id='acme',
                      permissions=['security.lockout.manage', 'security.lockout.view'])
    locked = time.time() + 3600
    ppglobals.login_attempts_by_user.clear()
    for name in ('alma', 'boss', 'gus', 'root'):
        ppglobals.login_attempts_by_user[name] = {'attempts': [time.time()], 'locked_until': locked}
    yield {'helen': api.as_user(helen), 'root': api.as_user({'username': 'root', 'role': 'admin'})}
    ppglobals.login_attempts_by_user.clear()


def _expired_by(client, monkeypatch):
    saved = {}
    monkeypatch.setattr(usersapi, 'save_users', lambda users: saved.update(users))
    r = client.post('/api/security/password-expiry/reset-all', json={'include_admins': True})
    assert r.status_code == 200, r.get_json()
    old = (datetime.now().year - 20)
    return {u for u, rec in saved.items()
            if (rec.get('password_changed_at') or '9999')[:4].isdigit()
            and int((rec.get('password_changed_at') or '9999')[:4]) < old}


def test_a_tenant_delegate_expires_only_what_it_could_reset(lockout_estate, monkeypatch):
    got = _expired_by(lockout_estate['helen'], monkeypatch)
    assert 'gus' not in got, "expired another tenant's password"
    assert 'root' not in got and 'boss' not in got, "expired an administrator's password"
    assert 'alma' in got


def test_a_global_admin_still_expires_everyone(lockout_estate, monkeypatch):
    assert {'alma', 'boss', 'gus', 'root'} <= _expired_by(lockout_estate['root'], monkeypatch)


def test_a_tenant_delegate_unlocks_only_its_tenants_users(lockout_estate):
    r = lockout_estate['helen'].delete('/api/security/locked-users')
    assert r.status_code == 200, r.get_json()
    left = set(ppglobals.login_attempts_by_user)
    assert {'gus', 'root'} <= left, "cleared another tenant's lockouts"
    assert 'alma' not in left


def test_a_global_admin_still_unlocks_everyone(lockout_estate):
    assert lockout_estate['root'].delete('/api/security/locked-users').status_code == 200
    assert not ppglobals.login_attempts_by_user


# --- the OIDC connection test does not follow a JWKS redirect ------------------------------

def _oidc_test(api, seed, monkeypatch, jwks_response):
    import pegaprox.api.auth as authapi
    calls = []
    monkeypatch.setattr(authapi, 'get_oidc_endpoints', lambda config: {
        'authorization': 'https://idp.example.test/authorize',
        'jwks': 'https://idp.example.test/jwks', '_discovery_used': True})
    monkeypatch.setattr(authapi, 'sanitize_outbound_url', lambda url, allow_private=False: url)

    def fake_get(url, **kw):
        calls.append((url, kw))
        if url.endswith('/jwks'):
            return jwks_response
        return MagicMock(status_code=200)

    monkeypatch.setattr(authapi.requests, 'get', fake_get)
    r = api.as_user(seed.user('root', role='admin')).post('/api/settings/oidc/test', json={})
    assert r.status_code == 200, r.get_json()
    step = next(s for s in r.get_json()['results'] if s['step'] == 'JWKS Endpoint')
    return step, dict(calls)['https://idp.example.test/jwks']


def test_a_jwks_redirect_is_not_followed(api, seed, monkeypatch):
    step, kw = _oidc_test(api, seed, monkeypatch, MagicMock(
        status_code=302, headers={'Location': 'http://169.254.169.254/'}))
    assert kw.get('allow_redirects', True) is False, 'the redirect target skipped the guard'
    assert step['status'] != 'ok'


def test_a_plain_jwks_answer_still_reports_its_keys(api, seed, monkeypatch):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {'keys': [{'kid': 'a'}, {'kid': 'b'}]}
    step, _ = _oidc_test(api, seed, monkeypatch, resp)
    assert step['status'] == 'ok' and '2 signing keys' in step['detail']


# --- the chargeback lists only the guests the caller may see -------------------------------

@pytest.fixture
def billed(api, seed, monkeypatch):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    rbac.invalidate_tenants_cache()
    mgr = api.make_fake_manager(CL, get_vm_resources=[
        {'vmid': 100, 'name': 'mine', 'node': 'n1', 'type': 'qemu', 'maxdisk': 0},
        {'vmid': 200, 'name': 'theirs', 'node': 'n1', 'type': 'qemu', 'maxdisk': 0}])
    mgr.config.name = CL
    api.set_manager(CL, mgr)
    vm = {'cpu': 10, 'mem': 10, 'maxmem': 1024 ** 3, 'maxcpu': 1, 'r': 1, 't': 'qemu'}
    monkeypatch.setattr(costs, '_load_history',
                        lambda cid, days=30: [(time.time(), {'vms': {'100': vm, '200': vm}})])
    _membership(CL, {100: ('qemu', 'p1'), 200: ('qemu', 'p2')})
    return seed


def _billed_vms(client):
    r = client.get('/api/tenants/t/chargeback')
    assert r.status_code == 200, r.get_json()
    return {str(row['vmid']) for row in r.get_json()['rows']}, r.get_json()


def test_a_pool_confined_delegate_sees_only_its_guests(api, billed):
    billed.pool(CL, 'p1', 'pia', ['pool.view', 'vm.view'])
    pia = api.as_user(billed.user('pia', role='user', tenant_id='t', permissions=['admin.tenants']))
    vms, body = _billed_vms(pia)
    assert vms == {'100'}, f'listed guests outside the grant: {vms}'
    assert body['by_cluster'][0]['vm_count'] == 1


def test_an_unconfined_tenant_operator_sees_the_whole_statement(api, billed):
    otto = api.as_user(billed.user('otto', role='user', tenant_id='t', permissions=['admin.tenants']))
    assert _billed_vms(otto)[0] == {'100', '200'}


def test_a_global_admin_sees_the_whole_statement(api, billed):
    assert _billed_vms(api.as_user(billed.user('root', role='admin')))[0] == {'100', '200'}


# --- an unreadable tenant table is no "no range" -------------------------------------------

def _unreadable(monkeypatch):
    monkeypatch.setattr(rbac, 'load_tenants', lambda: rbac._Snapshot(unavailable=True))


def test_a_vmid_is_refused_while_the_range_cannot_be_read(db, monkeypatch):
    _unreadable(monkeypatch)
    ok, msg = rbac.check_tenant_vmid('tenant_x', 4242)
    assert ok is False and 'Cannot verify' in msg


def test_nothing_named_is_still_nothing_to_judge(db, monkeypatch):
    _unreadable(monkeypatch)
    assert rbac.check_tenant_vmid('tenant_x', None) == (True, '')


def test_a_readable_table_judges_as_before(db, seed):
    seed.db.save_tenant('tenant_r', {'name': 'r', 'clusters': [], 'vmid_range_start': 1000,
                                     'vmid_range_end': 1999})
    seed.tenant('tenant_n', [])
    assert rbac.check_tenant_vmid('tenant_r', 1500)[0] is True
    assert rbac.check_tenant_vmid('tenant_r', 4242)[0] is False
    assert rbac.check_tenant_vmid('tenant_n', 4242) == (True, '')
