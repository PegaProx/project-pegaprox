"""A tenant cannot put its cluster into a global group (#986).

assign_cluster_to_group checked the target group with `group['tenant_id'] and ...`, which
lets a NULL-tenant (global) group through. update/delete/status/balance-now of a group
already treat a global group as admin-only for a tenant-scoped caller. The assignment
matters because cross-cluster balancing of a global group loads its members with no
tenant filter: an admin's live balance on that group could then move other tenants'
guests onto the tenant's cluster. The refusal reads like every other group route's for
such a caller: the group is not found.
"""
import pytest

from tests.conftest import make_fake_manager


@pytest.fixture
def estate(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=[])
    api.set_manager('cluster_1', make_fake_manager('cluster_1'))
    db = seed.db
    db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                  VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    for gid, name, tid in (('g_a', 'Tenant A', 'tenant_a'),
                           ('g_b', 'Tenant B', 'tenant_b'),
                           ('g_glob', 'Global', None)):
        db.execute('''INSERT INTO cluster_groups (id, name, description, color, tenant_id,
                      sort_order, created_at, updated_at)
                      VALUES (?, ?, '', '#fff', ?, 0, '2026-01-01', '2026-01-01')''',
                   (gid, name, tid))
    return db


def _group_of(db):
    return db.query_one("SELECT group_id FROM clusters WHERE id = 'cluster_1'")['group_id']


def _assign(api, user, gid):
    return api.as_user(user).put('/api/clusters/cluster_1/group', json={'group_id': gid})


def _tenant_admin(seed):
    return seed.user('tom', role='user', tenant_id='tenant_a', permissions=['admin.groups'])


def test_a_tenant_cannot_put_its_cluster_into_a_global_group(api, seed, estate):
    r = _assign(api, _tenant_admin(seed), 'g_glob')

    assert _group_of(estate) is None, 'the tenant moved its cluster into the global group'
    assert r.status_code == 404, r.get_data(as_text=True)


def test_the_refusal_is_audited(api, seed, estate):
    _assign(api, _tenant_admin(seed), 'g_glob')
    assert estate.query("SELECT id FROM audit_log WHERE action = 'cluster.group_assign_denied'")


def test_another_tenants_group_reads_as_missing_too(api, seed, estate):
    r = _assign(api, _tenant_admin(seed), 'g_b')
    missing = _assign(api, _tenant_admin(seed), 'g_nope')
    assert _group_of(estate) is None
    assert r.status_code == missing.status_code == 404


def test_a_tenant_still_uses_its_own_group(api, seed, estate):
    r = _assign(api, _tenant_admin(seed), 'g_a')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _group_of(estate) == 'g_a'


def test_an_admin_puts_a_cluster_into_a_global_group(api, seed, estate):
    r = _assign(api, seed.user('root', role='admin'), 'g_glob')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _group_of(estate) == 'g_glob'


def test_the_default_tenant_keeps_what_it_had(api, seed, estate):
    """Unscoped, as everywhere in this file: a global group yes, a tenant's group no."""
    dora = seed.user('dora', role='user', permissions=['admin.groups'])
    assert _assign(api, dora, 'g_glob').status_code == 200
    assert _group_of(estate) == 'g_glob'
    assert _assign(api, dora, 'g_b').status_code == 403
    assert _group_of(estate) == 'g_glob'
