"""What a tenant delegate or a confined caller reads and clears stays inside its scope.

A tenant admin holding admin.users could read a user of its own tenant "as seen from"
any other tenant: the permissions route took tenant_id from the query as given and
returned every tenant override the user held. That told it how another tenant's roles
resolve. A tenant-scoped caller now always reads its own tenant, and only that
tenant's override.

The legacy scheduled task list was filtered by cluster only, so a caller confined to a
pool or to ACL'd guests got the task of every guest on the cluster, with node and
schedule. The /api/schedules list did the per-guest pass, but skipped it for a
default-tenant account, whose reach is "every cluster" even with a pool grant. Both
now keep a confined caller to the tasks of guests it may see.

An IP lockout belongs to no tenant: it holds back every account tried from that
address, and the OIDC callback limit sits in the same store. A tenant delegate with
security.lockout.manage cleared one or all of them for every tenant. Only a global
admin does that now, and a delegate is not shown the IP entries.

Each test checks that the legitimate path (a global admin, a plain operator, the
delegate's own tenant) still works.
MK Oct 2026
"""
import json
import time

import pytest

import pegaprox.globals as ppglobals
import pegaprox.api.auth as authapi
from pegaprox.api.schedules import save_schedules
from pegaprox.background.scheduler import save_scheduled_tasks

from test_audit_bola_med_2026_09 import _seed_pool_membership

CID = 'cluster_1'


# --- user permissions read by a tenant admin --------------------------------------------

@pytest.fixture
def two_tenants(seed, db):
    from pegaprox.utils.rbac import invalidate_roles_cache
    seed.tenant('tenant_a', clusters=['cluster_a'])
    seed.tenant('tenant_b', clusters=['cluster_b'])
    for name, tid, perms in (('ops', 'tenant_a', ['vm.view']),
                             ('ops', 'tenant_b', ['vm.view', 'vm.delete', 'node.shell']),
                             ('b_ops', 'tenant_b', ['vm.view', 'vm.start', 'storage.view'])):
        db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, created_at) "
                        "VALUES (?, ?, ?, ?, '2026-01-01')", (name, json.dumps(perms), name, tid))
    db.conn.commit()
    invalidate_roles_cache()
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('carol', role='ops', tenant_id='tenant_a', tenant_permissions={
        'tenant_a': {'role': 'ops', 'extra': ['vm.console'], 'denied': []},
        'tenant_b': {'role': 'b_ops', 'extra': ['vm.migrate'], 'denied': []}})
    yield alice
    invalidate_roles_cache()


def _perms(client, query=None):
    r = client.get('/api/users/carol/permissions', query_string=query or {})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def test_a_tenant_admin_cannot_read_a_user_as_another_tenant(api, two_tenants):
    body = _perms(api.as_user(two_tenants), {'tenant_id': 'tenant_b'})
    assert body['tenant_id'] == 'tenant_a'
    assert body['effective_role'] == 'ops'
    eff = set(body['effective_permissions'])
    # tenant_b's 'ops' and 'b_ops' and the tenant_b extra do not come through
    assert not eff & {'vm.delete', 'node.shell', 'vm.start', 'storage.view', 'vm.migrate'}, eff
    assert 'vm.delete' not in body['role_permissions']


def test_a_tenant_admin_sees_only_its_own_tenants_override(api, two_tenants):
    body = _perms(api.as_user(two_tenants))
    assert set(body['tenant_permissions']) == {'tenant_a'}
    # counterproof: the user's own tenant still reads in full
    assert body['tenant_permissions']['tenant_a']['extra'] == ['vm.console']
    assert {'vm.view', 'vm.console'} <= set(body['effective_permissions'])


def test_a_global_admin_still_reads_any_tenant(api, seed, two_tenants):
    root = api.as_user(seed.user('root', role='admin'))
    body = _perms(root, {'tenant_id': 'tenant_b'})
    assert body['tenant_id'] == 'tenant_b' and body['effective_role'] == 'b_ops'
    assert {'vm.start', 'vm.migrate'} <= set(body['effective_permissions'])
    assert set(_perms(root)['tenant_permissions']) == {'tenant_a', 'tenant_b'}


# --- scheduled tasks of guests a confined caller may not see ----------------------------

@pytest.fixture
def estate(api, seed):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['cluster_other'])
    m = api.make_fake_manager(CID)
    m.is_connected = True
    api.set_manager(CID, m)
    save_scheduled_tasks({'tasks': [
        {'id': 't1', 'cluster_id': CID, 'name': 'mine', 'action': 'snapshot',
         'target_type': 'qemu', 'target_id': '100', 'target_node': 'pve1'},
        {'id': 't2', 'cluster_id': CID, 'name': 'mine-legacy', 'action': 'start',
         'target_type': 'vm', 'target_id': '100', 'target_node': 'pve1'},
        {'id': 't3', 'cluster_id': CID, 'name': 'theirs', 'action': 'stop',
         'target_type': 'qemu', 'target_id': '200', 'target_node': 'pve2'},
        {'id': 't4', 'cluster_id': CID, 'name': 'no-target', 'action': 'snapshot',
         'target_type': 'vm', 'target_id': '', 'target_node': ''},
        {'id': 't5', 'cluster_id': 'cluster_other', 'name': 'other-tenant', 'action': 'start',
         'target_type': 'qemu', 'target_id': '5', 'target_node': 'x1'},
    ]})
    save_schedules({'actions': [
        {'id': 1, 'cluster_id': CID, 'vmid': 100, 'vm_type': 'qemu', 'action': 'start',
         'schedule_type': 'daily', 'time': '02:00', 'enabled': True, 'created_by': 'root'},
        {'id': 2, 'cluster_id': CID, 'vmid': 200, 'vm_type': 'qemu', 'action': 'stop',
         'schedule_type': 'daily', 'time': '03:00', 'enabled': True, 'created_by': 'root'},
    ]})
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'other')})
    return seed


def _confined(seed, shape):
    if shape == 'pool_in_owning_tenant':
        seed.pool(CID, 'pool_1', 'olga', ['pool.view', 'vm.view'])
        return seed.user('olga', role='viewer', tenant_id='acme')
    if shape == 'pool_in_default_tenant':
        seed.pool(CID, 'pool_1', 'dora', ['pool.view', 'vm.view'])
        return seed.user('dora', role='viewer')
    seed.vm_acl(CID, 100, users=['petra'])
    return seed.user('petra', role='viewer', tenant_id='acme')


def _task_names(client):
    r = client.get('/api/scheduled-tasks')
    assert r.status_code == 200, r.get_json()
    return sorted(t['name'] for t in r.get_json()['tasks'])


def _action_vmids(client):
    r = client.get('/api/schedules')
    assert r.status_code == 200, r.get_json()
    return sorted(a['vmid'] for a in r.get_json())


@pytest.mark.parametrize('shape', ['pool_in_owning_tenant', 'pool_in_default_tenant', 'acl_in_owning_tenant'])
def test_a_confined_caller_lists_only_tasks_of_its_own_guests(api, estate, shape):
    c = api.as_user(_confined(estate, shape))
    names = _task_names(c)
    assert 'theirs' not in names, names
    assert 'no-target' not in names, names
    # counterproof: the task of its own guest stays, the legacy 'vm' target type too
    assert {'mine', 'mine-legacy'} <= set(names), names


def test_a_default_tenant_pool_holder_lists_only_its_guests_schedules(api, estate):
    c = api.as_user(_confined(estate, 'pool_in_default_tenant'))
    assert _action_vmids(c) == [100]


def test_a_pool_grant_from_another_tenant_shows_only_that_pools_guest(api, estate):
    estate.pool(CID, 'pool_1', 'gina', ['pool.view', 'vm.view'])
    names = _task_names(api.as_user(estate.user('gina', role='viewer', tenant_id='globex')))
    assert 'theirs' not in names and 'no-target' not in names, names
    assert {'mine', 'other-tenant'} <= set(names), names


def test_plain_operators_and_admins_still_list_everything(api, estate):
    everything = ['mine', 'mine-legacy', 'no-target', 'other-tenant', 'theirs']
    root = api.as_user(estate.user('root', role='admin'))
    assert _task_names(root) == everything
    assert _action_vmids(root) == [100, 200]
    # an operator of the owning tenant with no pool or ACL is not confined on its cluster
    ops = api.as_user(estate.user('ops', role='user', tenant_id='acme'))
    assert _task_names(ops) == ['mine', 'mine-legacy', 'no-target', 'theirs']
    # and a default-tenant account without any grant keeps every action
    assert _action_vmids(api.as_user(estate.user('dave', role='viewer'))) == [100, 200]


# --- IP lockouts and a tenant delegate --------------------------------------------------

LOCKED = ('203.0.113.7', '198.51.100.9')


@pytest.fixture
def lockouts(api, seed):
    seed.tenant('acme', [])
    seed.tenant('globex', [])
    seed.user('alma', role='user', tenant_id='acme')
    seed.user('gus', role='user', tenant_id='globex')
    helen = seed.user('helen', role='user', tenant_id='acme',
                      permissions=['security.lockout.manage', 'security.lockout.view'])
    root = seed.user('root', role='admin')
    until = time.time() + 3600
    store = authapi.login_attempts_by_ip
    assert store is ppglobals.login_attempts_by_ip
    store.clear()
    ppglobals.login_attempts_by_user.clear()
    for ip in LOCKED:
        store[ip] = {'attempts': [time.time()] * 5, 'locked_until': until}
    store['oidc_cb_203.0.113.7'] = {'attempts': [time.time()] * 3}
    for name in ('alma', 'gus'):
        ppglobals.login_attempts_by_user[name] = {'attempts': [time.time()], 'locked_until': until}
    yield {'helen': api.as_user(helen), 'root': api.as_user(root), 'store': store}
    store.clear()
    ppglobals.login_attempts_by_user.clear()


def test_a_tenant_delegate_cannot_lift_an_ip_lockout(lockouts):
    helen, store = lockouts['helen'], lockouts['store']
    assert helen.delete(f'/api/security/locked-ips/{LOCKED[0]}').status_code == 403
    assert helen.delete('/api/security/locked-ips').status_code == 403
    assert set(store) == set(LOCKED) | {'oidc_cb_203.0.113.7'}
    # counterproof: the delegate still lifts the lockout of its own tenant's account
    assert helen.delete('/api/security/locked-users/alma').status_code == 200
    assert 'alma' not in ppglobals.login_attempts_by_user


def test_a_tenant_delegate_is_not_shown_the_ip_entries(lockouts):
    body = lockouts['helen'].get('/api/security/locked-ips').get_json()
    assert body['locked_ips'] == [] and body['total_tracked_ips'] == 0
    assert [u['username'] for u in body['locked_users']] == ['alma']


def test_a_global_admin_still_manages_ip_lockouts(lockouts):
    root, store = lockouts['root'], lockouts['store']
    body = root.get('/api/security/locked-ips').get_json()
    assert sorted(x['ip'] for x in body['locked_ips']) == sorted(LOCKED)
    assert body['total_tracked_ips'] == 3
    assert root.delete(f'/api/security/locked-ips/{LOCKED[0]}').status_code == 200
    assert LOCKED[0] not in store
    assert root.delete('/api/security/locked-ips').status_code == 200
    assert store == {}
