# PUT /api/users/<user>/permissions took the permission lists from the body unchecked and
# went straight into `extra + denied`. A string next to a list, or an object, was a 500; two
# strings were walked letter by letter and answered "Invalid permission: v". Malformed lists
# now get a 400 that names the fields, nothing is stored, and well-formed calls are unchanged.
# Found by the daily CodeAnt scan. MK Oct 2026

import pytest


def _delegate(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('delegate', role='viewer', tenant_id='acme',
                     permissions=['admin.users', 'vm.view'])


def _tenant_perms(db, username):
    return (db.get_user(username) or {}).get('tenant_permissions') or {}


@pytest.mark.parametrize('extra, denied', [
    ('vm.view', []),
    ({'vm.view': True}, []),
    (['vm.view'], 'vm.delete'),
    ([['vm.view']], []),
    ([1], []),
])
def test_a_malformed_tenant_list_is_a_400_and_stores_nothing(db, api, seed, extra, denied):
    d = _delegate(seed)
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'extra': extra, 'denied': denied})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'must be lists of permission names' in r.get_json()['error']
    assert _tenant_perms(db, 'bob') == {}


def test_a_null_tenant_list_counts_as_empty(db, api, seed):
    d = _delegate(seed)
    seed.user('bob', role='viewer', tenant_id='acme')

    r = api.as_user(d).put('/api/users/bob/permissions',
                           json={'tenant_id': 'acme', 'extra': ['vm.view'], 'denied': None})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _tenant_perms(db, 'bob')['acme']['extra'] == ['vm.view']
    assert _tenant_perms(db, 'bob')['acme']['denied'] == []


@pytest.mark.parametrize('permissions, denied', [
    ('vm.view', []),
    (['vm.view'], {'vm.delete': 1}),
])
def test_a_malformed_global_list_is_a_400_and_stores_nothing(db, api, seed, permissions, denied):
    admin = seed.user('root2', role='admin')
    seed.user('carol', role='viewer')

    r = api.as_user(admin).put('/api/users/carol/permissions',
                               json={'permissions': permissions, 'denied_permissions': denied})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'must be lists of permission names' in r.get_json()['error']
    assert not (db.get_user('carol') or {}).get('permissions')


def test_a_well_formed_global_list_is_stored(db, api, seed):
    admin = seed.user('root2', role='admin')
    seed.user('carol', role='viewer')

    r = api.as_user(admin).put('/api/users/carol/permissions',
                               json={'permissions': ['vm.view'], 'denied_permissions': []})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert (db.get_user('carol') or {}).get('permissions') == ['vm.view']
