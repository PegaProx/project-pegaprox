"""Creating a custom role through the API, and what a user holding it actually gets.

The resolution side was fixed in 75d3a85 (a tenant-scoped role fell through to the
ROLE_VIEWER defaults). This walks the other half: create -> assign -> use -> edit
-> delete, through the real routes, checking at each step that the holder ends up
with exactly the permissions the role defines. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


VIEWER_ONLY = {'vm.view', 'vm.console'}


@pytest.fixture
def admin(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=[]))
    return api.as_user(seed.user('root_admin', role='admin'))


def _perms_of(username):
    from pegaprox.core.db import get_db
    u = dict(get_db().get_user(username))
    u['username'] = username
    return set(rbac.get_user_permissions(u))


def test_create_a_global_role_and_assign_it(admin, api, seed):
    r = admin.post('/api/roles', json={'id': 'globalops', 'name': 'Global Ops',
                                       'permissions': ['vm.view', 'vm.backup']})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]

    seed.user('gu', role='globalops', tenant_id='default')
    assert _perms_of('gu') == {'vm.view', 'vm.backup'}


def test_create_a_tenant_role_and_assign_it(admin, api, seed):
    r = admin.post('/api/roles', json={'id': 'acmeops', 'name': 'Acme Ops',
                                       'permissions': ['vm.view', 'vm.start', 'vm.snapshot'],
                                       'tenant_id': 'acme'})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]

    seed.user('tu', role='acmeops', tenant_id='acme')
    assert _perms_of('tu') == {'vm.view', 'vm.start', 'vm.snapshot'}


def test_a_tenant_role_holder_in_the_default_tenant_gets_the_same(admin, api, seed):
    """The case 75d3a85 fixed — assigning a role does not pin tenant_id."""
    admin.post('/api/roles', json={'id': 'acmeops2', 'permissions': ['vm.view', 'vm.start'],
                                   'tenant_id': 'acme'})

    seed.user('du', role='acmeops2', tenant_id='default')
    assert _perms_of('du') == {'vm.view', 'vm.start'}


def test_applying_a_template_produces_its_permissions(admin, api, seed):
    from pegaprox.utils.rbac import ROLE_TEMPLATES
    r = admin.post('/api/roles/templates/vm_operator/apply',
                   json={'role_id': 'vmops', 'tenant_id': 'acme'})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]

    seed.user('vu', role='vmops', tenant_id='acme')
    assert _perms_of('vu') == set(ROLE_TEMPLATES['vm_operator']['permissions'])


def test_a_template_role_withholds_what_the_template_withholds(admin, api, seed):
    """vm_operator is documented "VMs only - no infra access"."""
    admin.post('/api/roles/templates/vm_operator/apply',
               json={'role_id': 'vmops2', 'tenant_id': 'acme'})
    seed.user('vu2', role='vmops2', tenant_id='acme')

    perms = _perms_of('vu2')
    for withheld in ('node.shell', 'cluster.config', 'storage.config', 'admin.users'):
        assert withheld not in perms, withheld


def test_editing_a_role_takes_effect_immediately(admin, api, seed):
    """get_custom_roles is cached in a module global; the write path has to invalidate it."""
    admin.post('/api/roles', json={'id': 'editme', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})
    seed.user('eu', role='editme', tenant_id='acme')
    assert _perms_of('eu') == {'vm.view'}

    r = admin.put('/api/roles/editme', json={'permissions': ['vm.view', 'vm.start'],
                                             'tenant_id': 'acme'})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]

    assert _perms_of('eu') == {'vm.view', 'vm.start'}, 'the role cache went stale'


def test_a_role_id_cannot_shadow_a_builtin(admin):
    assert admin.post('/api/roles', json={'id': 'admin', 'permissions': []}).status_code == 400


def test_an_unknown_permission_is_refused(admin):
    r = admin.post('/api/roles', json={'id': 'bogus', 'permissions': ['vm.view', 'not.a.perm']})

    assert r.status_code == 400
    assert 'not.a.perm' in r.get_data(as_text=True)


def test_deleting_a_role_someone_still_holds_is_refused(admin, api, seed):
    """The resolver falls back to the ROLE_VIEWER defaults for a name it cannot resolve, so
    deleting a deliberately narrow role used to WIDEN its holders to 31 permissions — the
    whole node, cluster and PBS read surface. An admin deleting a role means "revoke this"."""
    admin.post('/api/roles', json={'id': 'narrow', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})
    seed.user('nu', role='narrow', tenant_id='acme')
    assert _perms_of('nu') == {'vm.view'}

    r = admin.delete('/api/roles/narrow?tenant_id=acme')

    assert r.status_code == 409, r.get_data(as_text=True)[:200]
    assert 'nu' in r.get_json()['users']
    assert _perms_of('nu') == {'vm.view'}, 'the holder was widened anyway'


def test_a_role_nobody_holds_deletes_normally(admin, api, seed):
    """The guard must not make an unused role undeletable."""
    admin.post('/api/roles', json={'id': 'unused', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})

    r = admin.delete('/api/roles/unused?tenant_id=acme')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert 'unused' not in admin.get('/api/roles').get_data(as_text=True)


def test_reassigning_the_holder_then_deleting_works(admin, api, seed):
    """The workflow the 409 points at."""
    admin.post('/api/roles', json={'id': 'narrow2', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})
    seed.user('nu2', role='narrow2', tenant_id='acme')
    assert admin.delete('/api/roles/narrow2?tenant_id=acme').status_code == 409

    assert admin.put('/api/users/nu2', json={'role': 'viewer'}).status_code == 200

    assert admin.delete('/api/roles/narrow2?tenant_id=acme').status_code == 200


def test_a_tenant_override_also_counts_as_holding_the_role(admin, api, seed):
    """tenant_permissions[tid]['role'] is the other way to hold a role."""
    admin.post('/api/roles', json={'id': 'narrow3', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})
    u = seed.user('nu3', role='viewer', tenant_id='default')
    from pegaprox.core.db import get_db
    get_db().save_user('nu3', {**u, 'tenant_permissions': {'acme': {'role': 'narrow3'}}})

    r = admin.delete('/api/roles/narrow3?tenant_id=acme')

    assert r.status_code == 409, r.get_data(as_text=True)[:200]
    assert 'nu3' in r.get_json()['users']


def test_a_rejected_update_does_not_partially_apply(admin, api, seed):
    """get_custom_roles hands back the live cached dict, and the name was written into it
    before the permission list was validated — so a 400 still renamed the role for the rest
    of the process's life, with nothing on disk to match."""
    admin.post('/api/roles', json={'id': 'renameme', 'name': 'Original',
                                   'permissions': ['vm.view'], 'tenant_id': 'acme'})

    r = admin.put('/api/roles/renameme', json={'name': 'Rewritten',
                                               'permissions': ['vm.view', 'not.a.perm'],
                                               'tenant_id': 'acme'})

    assert r.status_code == 400, r.get_data(as_text=True)[:200]
    roles = admin.get('/api/roles').get_json()
    listed = str(roles)
    assert 'Original' in listed, 'the rejected rename applied anyway'
    assert 'Rewritten' not in listed


def test_a_rejected_update_leaves_the_permissions_alone(admin, api, seed):
    admin.post('/api/roles', json={'id': 'keepperms', 'permissions': ['vm.view'],
                                   'tenant_id': 'acme'})
    seed.user('ku', role='keepperms', tenant_id='acme')

    admin.put('/api/roles/keepperms', json={'permissions': ['vm.view', 'bogus.perm'],
                                            'tenant_id': 'acme'})

    assert _perms_of('ku') == {'vm.view'}
