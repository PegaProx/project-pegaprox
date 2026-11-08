"""404 for absent, 403 for someone else's — the pair is the leak.

Every cluster-group route looked the record up, answered 404 when it was absent
and 403 when it belonged to another tenant. Neither answer is wrong on its own;
together they let a tenant-scoped caller walk group ids and learn which ones
exist purely from the status code, without ever being allowed to see one.

The authorization rule is unchanged and stays where the earlier hardening put it:
a tenant-scoped caller may act on their own tenant's groups only, and a global
(tenant_id NULL) group is admin-only. What changed is what the caller is TOLD.
The audit entries for a denial are untouched — that is about what we keep, not
about what we disclose, and the two routes that logged a denial still do.

Aikido ai_pentest 700486886. NS
"""
import pytest

OWNER = 'acme'
OTHER = 'globex'


@pytest.fixture
def groups(api, seed, db):
    seed.tenant(OWNER, clusters=[])
    seed.tenant(OTHER, clusters=[])
    db.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES (?, ?, ?)",
               ('grp_mine', 'Mine', OWNER))
    db.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES (?, ?, ?)",
               ('grp_theirs', 'Theirs', OTHER))
    db.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES (?, ?, ?)",
               ('grp_global', 'Global', None))
    db.conn.commit()
    return db


@pytest.fixture
def tenant_user(api, seed, groups):
    return api.as_user(seed.user('acme_admin', role='user', tenant_id=OWNER,
                                 permissions=['admin.groups', 'cluster.view',
                                              'cluster.config']))


def _status(client, gid):
    return client.get(f'/api/cluster-groups/{gid}/status').status_code


def test_another_tenants_group_is_indistinguishable_from_a_missing_one(tenant_user):
    foreign = _status(tenant_user, 'grp_theirs')
    missing = _status(tenant_user, 'grp_does_not_exist')

    assert foreign == missing, (
        f"status code tells them the group exists: foreign={foreign} missing={missing}")
    assert foreign == 404


def test_a_global_group_is_also_indistinguishable(tenant_user):
    """A NULL-tenant group is admin-only for a scoped caller, by the earlier
    hardening. It must not be distinguishable either."""
    assert _status(tenant_user, 'grp_global') == _status(tenant_user, 'nope') == 404


def test_the_caller_still_sees_their_own_group(tenant_user):
    """The mirror — normalising to 404 must not hide a group from its owner."""
    assert _status(tenant_user, 'grp_mine') != 404


def test_an_admin_sees_every_group(api, seed, groups):
    boss = api.as_user(seed.user('boss', role='admin'))
    for gid in ('grp_mine', 'grp_theirs', 'grp_global'):
        assert _status(boss, gid) != 404, gid


def test_the_denial_is_still_recorded(tenant_user, db):
    """What the caller is told changed; what we keep did not."""
    tenant_user.post('/api/cluster-groups/grp_theirs/balance-now', json={})
    rows = db.query("SELECT action FROM audit_log WHERE action LIKE 'xclb.manual_denied%'")
    assert rows, 'the denial stopped being audited'
