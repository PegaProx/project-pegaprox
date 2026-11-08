"""An admin a tenant override lowers where they live is that role everywhere.

tenant_permissions is written by the directory group mappings, so "admin globally, viewer
(or a tenant role) inside acme" is a configuration an operator produces from their
directory. has_permission and get_user_clusters have honoured the lowering since Aikido
700487698; every other admin shortcut compared the stored role and let the account
through: caller_is_scoped, user_can_access_vm, user_has_any_pool_access, get_user_vms,
user_can_access_vmware_vm, the PBS gates, every roles=[ROLE_ADMIN] route (the scheduled
tasks, which run start/stop/backup against any cluster's guests, among them) and the
"global admin" checks of the user, tenant and role routes, which read
request.session['role']. The notifications and status page plugins kept their own copy of
the stored-role check, and creating or deleting a tenant asked no tenant question at all.

The ordinary admin, an override that restates admin, and an API token scoped below its
admin owner keep what they had - the token gets a little more: it used to count as
confined everywhere, because user_has_any_pool_access read the owner's stored role.

(#1028, #1031, #1000, #1060, #1096) MK
"""
import json

import pytest

import pegaprox.api.history as history
import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped
from pegaprox.models.permissions import ROLE_PERMISSIONS
from pegaprox.utils.auth import apply_token_role

OWN, FOREIGN = 'cluster_a', 'cluster_b'


@pytest.fixture
def tenants(seed):
    seed.tenant('acme', [OWN])
    seed.tenant('globex', [FOREIGN])


def _lowered(seed, role='viewer', name='alex'):
    """What ldap.py writes for 'admin globally, <role> inside acme'."""
    return seed.user(name, role='admin', tenant_id='acme',
                     tenant_permissions={'acme': {'role': role, 'extra': [], 'denied': []}})


def _tenant_role(db, name, perms, tenant='acme'):
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES (?, ?, 'x', ?, '2026-01-01T00:00:00')",
                    (name, json.dumps(perms), tenant))
    db.conn.commit()
    rbac.invalidate_roles_cache()


# --- the object-level shortcuts (#1028) --------------------------------------------------

def test_a_lowered_admin_is_confined_on_a_foreign_cluster(db, seed, tenants):
    assert caller_is_scoped(_lowered(seed), FOREIGN) is True


def test_a_lowered_admin_reaches_no_guest_on_a_foreign_cluster(db, seed, tenants):
    assert rbac.user_can_access_vm(_lowered(seed), FOREIGN, 100, 'vm.view') is False


def test_a_lowered_admin_holds_the_lowered_role_on_its_own_guests(db, seed, tenants):
    u = _lowered(seed)
    assert rbac.user_can_access_vm(u, OWN, 100, 'vm.view') is True
    assert rbac.user_can_access_vm(u, OWN, 100, 'vm.delete') is False


def test_a_lowered_admin_has_no_pool_access_it_was_not_granted(db, seed, tenants):
    assert rbac.user_has_any_pool_access(_lowered(seed), OWN) is False


def test_a_lowered_admins_vm_list_follows_its_acls(db, seed, tenants):
    rbac.invalidate_vm_acls_cache()
    u = _lowered(seed)
    seed.vm_acl(OWN, 100, ['alex'])
    rbac.invalidate_vm_acls_cache()
    assert rbac.get_user_vms(u, OWN) == [100]


def test_a_lowered_admin_reaches_no_foreign_esxi_guest(db, seed, tenants, monkeypatch):
    class _Esxi:
        linked_clusters = [FOREIGN]
    monkeypatch.setitem(ppglobals.vmware_managers, 'esxi1', _Esxi())
    assert rbac.user_can_access_vmware_vm(_lowered(seed), 'esxi1', 'vm-7') is False


def test_an_ordinary_admin_keeps_every_shortcut(db, seed, tenants, monkeypatch):
    class _Esxi:
        linked_clusters = [FOREIGN]
    monkeypatch.setitem(ppglobals.vmware_managers, 'esxi1', _Esxi())
    u = seed.user('root', role='admin', tenant_id='acme')
    assert caller_is_scoped(u, FOREIGN) is False
    assert rbac.user_can_access_vm(u, FOREIGN, 100, 'vm.delete') is True
    assert rbac.get_user_vms(u, FOREIGN) is None
    assert rbac.user_can_access_vmware_vm(u, 'esxi1', 'vm-7') is True


def test_an_override_restating_admin_is_no_lowering(db, seed, tenants):
    u = _lowered(seed, role='admin')
    assert caller_is_scoped(u, FOREIGN) is False
    assert rbac.user_can_access_vm(u, FOREIGN, 100, 'vm.delete') is True


def test_a_token_below_its_admin_owner_is_an_operator_not_confined(db, seed, tenants):
    """The owner's stored role made user_has_any_pool_access answer yes for the token,
    so every caller_is_scoped call counted it as confined."""
    owner = seed.user('root', role='admin')
    token = apply_token_role(owner, 'user')
    assert caller_is_scoped(token, OWN) is False
    assert rbac.user_has_any_pool_access(token, OWN) is False


def test_a_tenant_role_override_remaps_like_anyone_elses(db, seed):
    """A lowered admin of the DEFAULT tenant whose override names a tenant role gets that
    tenant's clusters, the way an ordinary holder of the role does - not every cluster."""
    seed.tenant('default', [])
    seed.tenant('acme', [OWN])
    _tenant_role(db, 'acmeops', ['vm.view'])
    u = seed.user('alex', role='admin', tenant_id='default',
                  tenant_permissions={'default': {'role': 'acmeops'}})
    assert rbac.get_user_clusters(u, include_pools=False) == [OWN]


# --- the PBS gates (#1031) ------------------------------------------------------------------

class _Pbs:
    connected = False
    last_status = None

    def __init__(self, name, linked):
        self.linked_clusters = list(linked)
        self.name = name
        self.gc_calls = []

    def start_gc(self, store):
        self.gc_calls.append(store)
        return {'data': 'UPID:x'}

    def to_dict(self):
        return {'id': self.name, 'linked_clusters': self.linked_clusters}


@pytest.fixture
def pbs(monkeypatch):
    shared, foreign = _Pbs('shared', [OWN, FOREIGN]), _Pbs('foreign', [FOREIGN])
    monkeypatch.setitem(ppglobals.pbs_managers, 'shared', shared)
    monkeypatch.setitem(ppglobals.pbs_managers, 'foreign', foreign)
    return shared, foreign


def test_a_lowered_admin_cannot_gc_a_shared_datastore(api, db, seed, tenants, pbs):
    shared, _ = pbs
    r = api.as_user(_lowered(seed, role='user')).post('/api/pbs/shared/datastores/s1/gc')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert shared.gc_calls == []


def test_a_lowered_admin_does_not_reach_a_foreign_pbs(api, db, seed, tenants, pbs):
    r = api.as_user(_lowered(seed)).get('/api/pbs/foreign/status')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_a_lowered_admin_does_not_list_a_foreign_pbs(api, db, seed, tenants, pbs):
    r = api.as_user(_lowered(seed)).get('/api/pbs')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'foreign' not in {s.get('id') for s in r.get_json()}
    assert 'shared' in {s.get('id') for s in r.get_json()}


def test_an_admin_still_reaches_every_pbs(api, db, seed, tenants, pbs):
    shared, _ = pbs
    admin = seed.user('root', role='admin')
    c = api.as_user(admin)
    assert c.get('/api/pbs/foreign/status').status_code == 503    # past the gate, not connected
    assert {s.get('id') for s in c.get('/api/pbs').get_json()} >= {'shared', 'foreign'}
    assert c.post('/api/pbs/shared/datastores/s1/gc').status_code == 200
    assert shared.gc_calls == ['s1']


# --- roles=[ROLE_ADMIN]: the scheduled tasks (#1000) ------------------------------------------

TASK = {'name': 'nightly', 'cluster_id': FOREIGN, 'target_type': 'qemu', 'target_id': '100',
        'target_node': 'n1', 'action': 'stop', 'schedule_type': 'daily', 'schedule_time': '02:00'}


@pytest.fixture
def ran(monkeypatch):
    calls = []
    monkeypatch.setattr(history, 'execute_scheduled_task', lambda t: calls.append(t.get('id')))
    return calls


def test_a_lowered_admin_cannot_write_a_scheduled_task(api, db, seed, tenants, ran):
    r = api.as_user(_lowered(seed)).post('/api/scheduled-tasks', json=TASK)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert history.load_scheduled_tasks().get('tasks', []) == []


def test_a_lowered_admin_cannot_run_one_an_admin_wrote(api, db, seed, tenants, ran):
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).post('/api/scheduled-tasks', json=TASK)
    assert r.status_code == 201, r.get_data(as_text=True)
    tid = r.get_json()['id']

    c = api.as_user(_lowered(seed))
    assert c.post(f'/api/scheduled-tasks/{tid}/run').status_code == 403
    assert c.delete(f'/api/scheduled-tasks/{tid}').status_code == 403
    assert ran == []


def test_an_admin_runs_scheduled_tasks_as_before(api, db, seed, tenants, ran):
    c = api.as_user(seed.user('root', role='admin'))
    tid = c.post('/api/scheduled-tasks', json=TASK).get_json()['id']
    assert c.post(f'/api/scheduled-tasks/{tid}/run').status_code == 200
    assert ran == [tid]
    assert c.delete(f'/api/scheduled-tasks/{tid}').status_code == 200


def test_the_lowered_role_is_what_the_request_publishes(api, db, seed, tenants):
    """Routes that read session['effective_role'] see the lowered role: the shared default
    power tariff is a global admin's, cluster.config inside acme does not reach it."""
    _tenant_role(db, 'acmeops', ['cluster.config', 'cluster.view', 'vm.view'])
    r = api.as_user(_lowered(seed, role='acmeops')).put('/api/power/rates/__default__',
                                                        json={'kwh_price': 9.99})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_a_lowered_admin_cannot_force_every_tenants_alerts(api, db, seed, tenants, monkeypatch):
    from pegaprox.background import alerts as A
    fired = []
    monkeypatch.setattr(A, 'check_and_send_alerts', lambda *a, **k: fired.append(1))
    _tenant_role(db, 'acmealerts', ['alert.manage', 'cluster.view'])
    r = api.as_user(_lowered(seed, role='acmealerts')).post('/api/alerts/force-check', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json().get('forced') is False
    assert fired == []


# --- the user, tenant and role routes (#1060, #1096) ------------------------------------------

@pytest.fixture
def lowered_tenant_admin(db, seed, tenants):
    """Lowered into acme's own admin role: admin.users and admin.tenants, inside acme."""
    _tenant_role(db, 'acmeadmin', ROLE_PERMISSIONS['viewer'] + ['admin.users', 'admin.tenants',
                                                                'admin.roles'])
    seed.user('carol', role='viewer', tenant_id='acme')
    seed.user('gus', role='viewer', tenant_id='globex')
    return _lowered(seed, role='acmeadmin')


def test_it_cannot_read_another_tenants_user(api, lowered_tenant_admin):
    c = api.as_user(lowered_tenant_admin)
    assert c.get('/api/users/gus/permissions').status_code == 404
    assert c.get('/api/users/gus/vm-access').status_code == 403


def test_it_cannot_write_another_tenants_permissions(api, db, lowered_tenant_admin):
    r = api.as_user(lowered_tenant_admin).put('/api/users/gus/permissions',
                                              json={'tenant_id': 'globex', 'denied': ['vm.view']})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert (db.get_user('gus') or {}).get('tenant_permissions') in ({}, None)


def test_it_cannot_touch_another_tenant(api, db, lowered_tenant_admin):
    c = api.as_user(lowered_tenant_admin)
    assert c.put('/api/tenants/globex', json={'name': 'pwned'}).status_code == 403
    assert c.get('/api/tenants/globex/quota').status_code == 403
    assert c.get('/api/tenants/globex/chargeback').status_code == 403
    assert {t['id'] for t in c.get('/api/tenants').get_json()} <= {'acme', 'default'}


def test_it_cannot_create_a_user_in_another_tenant(api, db, lowered_tenant_admin):
    r = api.as_user(lowered_tenant_admin).post('/api/users', json={
        'username': 'mole', 'password': 'Planted-2026!x', 'role': 'viewer', 'tenant_id': 'globex'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert db.get_user('mole') is None


def test_it_cannot_make_a_global_role(api, db, lowered_tenant_admin):
    r = api.as_user(lowered_tenant_admin).post('/api/roles', json={'id': 'everywhere',
                                                                   'permissions': ['vm.view']})
    assert r.status_code == 200, r.get_data(as_text=True)
    custom = rbac.load_custom_roles()
    assert 'everywhere' not in custom['global'], 'a lowered admin minted a global role'
    assert 'everywhere' in custom['tenants'].get('acme', {})


def test_it_still_manages_its_own_tenant(api, db, lowered_tenant_admin):
    c = api.as_user(lowered_tenant_admin)
    assert c.get('/api/users/carol/permissions').status_code == 200
    assert c.get('/api/tenants/acme/quota').status_code == 200
    r = c.put('/api/users/carol/permissions', json={'tenant_id': 'acme', 'denied': ['vm.console']})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_an_ordinary_admin_still_manages_every_tenant(api, db, seed, lowered_tenant_admin):
    c = api.as_user(seed.user('root', role='admin'))
    assert c.get('/api/users/gus/permissions').status_code == 200
    assert c.get('/api/users/gus/vm-access').status_code == 200
    assert c.get('/api/tenants/globex/quota').status_code == 200
    assert c.get('/api/tenants/globex/chargeback').status_code == 200
    assert {'acme', 'globex'} <= {t['id'] for t in c.get('/api/tenants').get_json()}


def test_it_cannot_lift_its_own_lowering(api, db, lowered_tenant_admin):
    """The override is all that stands between this account and a full admin: removing
    it, rewriting it, or leaving the tenant it governs would each undo the lowering."""
    c = api.as_user(lowered_tenant_admin)
    assert c.delete('/api/users/alex/tenant-permissions/acme').status_code == 403
    assert c.put('/api/users/alex/permissions',
                 json={'tenant_id': 'acme', 'role': 'acmeadmin', 'extra': []}).status_code == 403
    assert c.put('/api/users/alex', json={'tenant_id': 'default'}).status_code == 403
    alex = db.get_user('alex')
    assert alex['tenant_id'] == 'acme'
    assert alex['tenant_permissions']['acme']['role'] == 'acmeadmin'


def test_an_admin_token_it_mints_is_lowered_too(api, db, lowered_tenant_admin, ran):
    from pegaprox.utils.auth import create_api_token
    tok = create_api_token('alex', 'ci', role='admin')['token']
    c, h = api.anon(), {'Authorization': f'Bearer {tok}'}
    assert c.post('/api/scheduled-tasks', json=TASK, headers=h).status_code == 403
    assert c.get('/api/users/gus/permissions', headers=h).status_code == 404
    assert c.post('/api/tenants', json={'name': 'shadow'}, headers=h).status_code == 403
    assert ran == [] and history.load_scheduled_tasks().get('tasks', []) == []


def test_it_cannot_create_or_delete_a_tenant(api, db, seed, lowered_tenant_admin):
    """update_tenant confined a tenant-scoped admin.tenants holder to its own tenant and kept
    the cluster list for a global admin. Its two siblings asked nothing: a new tenant could
    name another tenant's clusters, and any tenant without accounts could be deleted."""
    seed.tenant('initech', ['cluster_i'])
    c = api.as_user(lowered_tenant_admin)

    r = c.post('/api/tenants', json={'name': 'shadow', 'clusters': [FOREIGN]})
    assert r.status_code == 403, r.get_data(as_text=True)
    r = c.delete('/api/tenants/initech')
    assert r.status_code == 403, r.get_data(as_text=True)

    assert 'initech' in rbac.load_tenants() and 'shadow' not in rbac.load_tenants()


def test_a_tenant_delegate_cannot_either(api, db, seed, tenants):
    _tenant_role(db, 'acmetenants', ROLE_PERMISSIONS['viewer'] + ['admin.tenants'])
    seed.tenant('initech', [])
    c = api.as_user(seed.user('dana', role='acmetenants', tenant_id='acme'))
    assert c.post('/api/tenants', json={'name': 'shadow'}).status_code == 403
    assert c.delete('/api/tenants/initech').status_code == 403
    assert 'initech' in rbac.load_tenants()


def test_an_admin_still_creates_and_deletes_tenants(api, db, seed, tenants):
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post('/api/tenants', json={'name': 'initech', 'clusters': [FOREIGN]})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert c.delete('/api/tenants/initech').status_code == 200
    assert 'initech' not in rbac.load_tenants()


# --- the plugins' own admin checks ---------------------------------------------------------

def _plugin(monkeypatch, name):
    """Load a bundled plugin and register its config route, without what its register()
    also does (alert handlers, the public status route)."""
    import importlib.util
    import pathlib
    import pegaprox.api.plugins as plugins_api
    src = pathlib.Path(__file__).resolve().parent.parent / 'plugins' / name / '__init__.py'
    spec = importlib.util.spec_from_file_location(f'_pp_test_plugin_{name}', src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setitem(plugins_api._loaded_plugins, name, mod)
    monkeypatch.setitem(plugins_api._plugin_routes, name, {'config': mod._get_config})
    return f'/api/plugins/{name}/api/config'


@pytest.mark.parametrize('name', ['notifications', 'status_page'])
def test_it_gets_no_plugin_admin_route(api, db, seed, lowered_tenant_admin, monkeypatch, name):
    """The notification targets (tokens, Apprise URLs with credentials in them) are where
    every tenant's alerts go, and the status page key publishes every cluster's state."""
    path = _plugin(monkeypatch, name)
    r = api.as_user(lowered_tenant_admin).get(path)
    assert r.status_code == 403, r.get_data(as_text=True)
    r = api.as_user(seed.user('root', role='admin')).get(path)
    assert r.status_code == 200, r.get_data(as_text=True)
