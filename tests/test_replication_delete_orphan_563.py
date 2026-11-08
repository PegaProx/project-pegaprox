"""Deleting a cross-cluster replication job: BOLA gate vs. the #563 orphan cleanup.

Two requirements pull against each other here. The per-VM gate stops a scoped
cluster.config holder from dropping (and with delete_target, tearing down) a
co-tenant's job. #563 says an admin who removed a cluster must still be able to
clean up the replication jobs it left behind — and once that cluster is gone
there are no ACLs or pool grants left to answer the ownership question with, so
an unconditional gate makes the orphan permanently undeletable.

The route's cluster-access loop already carves that out; the per-VM gate added
later did not, which re-broke #563. MK
"""
import pytest

import pegaprox.globals as ppglobals


MINE, THEIRS = 100, 200


def _seed_job(db, job_id, source, target, vmid, target_vmid=None):
    db.execute(
        "INSERT INTO cross_cluster_replications "
        "(id, source_cluster, target_cluster, vmid, vm_type, target_node) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (job_id, source, target, vmid, 'qemu', 'pve1'))


@pytest.fixture
def clusters(api):
    """cluster_1 and cluster_2 both registered and connected."""
    for cid in ('cluster_1', 'cluster_2'):
        m = api.make_fake_manager(cid)
        m.is_connected = True
        api.set_manager(cid, m)
    return ppglobals.cluster_managers


@pytest.fixture
def scoped(api, seed):
    """Tenant owns both clusters; the user holds a VM ACL on MINE only."""
    seed.tenant('tenant_a', clusters=['cluster_1', 'cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a',
                      permissions=['cluster.config'])
    seed.vm_acl('cluster_1', MINE, ['alice'], permissions=['vm.migrate', 'vm.view'])
    return api.as_user(alice)


def test_scoped_caller_cannot_delete_a_co_tenants_job(db, clusters, scoped):
    _seed_job(db, 'job_theirs', 'cluster_1', 'cluster_2', THEIRS)

    r = scoped.delete('/api/cross-cluster-replications/job_theirs')

    assert r.status_code == 403, r.get_data(as_text=True)[:300]
    assert db.query_one("SELECT id FROM cross_cluster_replications WHERE id = 'job_theirs'")


def test_scoped_caller_deletes_their_own_job(db, clusters, scoped):
    _seed_job(db, 'job_mine', 'cluster_1', 'cluster_2', MINE)

    r = scoped.delete('/api/cross-cluster-replications/job_mine')

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert db.query_one("SELECT id FROM cross_cluster_replications WHERE id = 'job_mine'") is None


def test_orphaned_job_stays_deletable_after_its_source_cluster_is_removed(db, api, seed):
    """#563. The source cluster is gone, so nothing can prove ownership of its guest —
    and the guest is gone too. The cleanup must not be gated on it."""
    seed.tenant('tenant_a', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a',
                      permissions=['cluster.config'])
    m = api.make_fake_manager('cluster_2')
    m.is_connected = True
    api.set_manager('cluster_2', m)
    _seed_job(db, 'job_orphan', 'cluster_gone', 'cluster_2', THEIRS)

    r = api.as_user(alice).delete('/api/cross-cluster-replications/job_orphan')

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert db.query_one("SELECT id FROM cross_cluster_replications WHERE id = 'job_orphan'") is None


def test_admin_deletes_either_way(db, clusters, api, seed):
    _seed_job(db, 'job_a', 'cluster_1', 'cluster_2', THEIRS)
    root = api.as_user(seed.user('root_admin', role='admin'))

    assert root.delete('/api/cross-cluster-replications/job_a').status_code == 200
