"""The last three findings from the round-12 batch.

  1. /api/ws/updates resolved identity, cluster scope and is_admin during the
     handshake and then froze them for the life of the socket — no re-check at
     all, not even a dead one. Its SSE twin now re-reads every 30s.
  2. A pool-membership rebuild reads every pool over the network, which takes
     seconds. An admin who revoked a grant in that window called
     invalidate_pool_cache(), we dropped the entry — and then the in-flight
     rebuild published its PRE-revocation snapshot with a fresh timestamp,
     re-pinning the revoked grant for another full TTL.
  3. The backup-verification status route resolved task_id with no cluster
     match, so a task belonging to another cluster answered on this cluster's
     URL — and an unconfined caller passes _verification_rows_visible unchanged.

MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.api.realtime as rt
import pegaprox.core.backup_verify as bv
import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


# ── 1. the WebSocket stream re-checks its account ────────────────────────────

def test_the_ws_loop_revalidates_on_a_clock():
    """Structural: the handshake block runs once, so the re-check has to live in the
    receive loop and be driven by its own clock, not by a message arriving."""
    # @sock.route does not leave the function bound on the module, so read the file
    src = open('pegaprox/api/realtime.py').read()
    handler = src[src.index("@sock.route('/api/ws/updates')"):]
    loop = handler[handler.index('while True:'):handler.index('WebSocket client disconnected')]

    assert '_stream_identity' in loop, 'the socket never re-reads the account'
    assert 'SSE_REAUTHZ_INTERVAL' in loop, 'the re-check is not on a clock'
    assert '_scope_ws_clusters' in loop, 'a demotion must narrow the live subscription'


# ── 2. a rebuild invalidated mid-read must not publish ───────────────────────

@pytest.fixture
def pool_cluster(monkeypatch):
    """A cluster whose pool read is slow enough for a revocation to land during it."""
    mgr = MagicMock()
    mgr.get_pools.return_value = [{'poolid': 'p1'}]
    monkeypatch.setattr(rbac, 'cluster_managers', {'c1': mgr})
    rbac._pool_membership_cache.clear()
    return mgr


def test_a_revocation_during_the_rebuild_is_not_overwritten(pool_cluster):
    """The revocation lands while get_pool_members is still on the wire."""
    def _members(pool_id):
        rbac.invalidate_pool_cache('c1')          # admin removes the VM from the pool
        return {'members': [{'vmid': 100, 'type': 'qemu'}]}   # our pre-revocation view
    pool_cluster.get_pool_members.side_effect = _members

    rbac._refresh_pool_cache_async('c1')

    assert 'c1' not in rbac._pool_membership_cache, \
        'the stale snapshot was published over the invalidation'


def test_an_undisturbed_rebuild_publishes_normally(pool_cluster):
    pool_cluster.get_pool_members.return_value = {'members': [{'vmid': 100, 'type': 'qemu'}]}

    rbac._refresh_pool_cache_async('c1')

    assert rbac._pool_membership_cache['c1']['data'] == {'100:qemu': 'p1'}


def test_the_initial_build_is_discarded_the_same_way(pool_cluster):
    def _members(pool_id):
        rbac.invalidate_pool_cache('c1')
        return {'members': [{'vmid': 100, 'type': 'qemu'}]}
    pool_cluster.get_pool_members.side_effect = _members

    membership = rbac.get_pool_membership_cache('c1')

    assert membership == {'100:qemu': 'p1'}, 'this caller still gets an answer'
    assert 'c1' not in rbac._pool_membership_cache, 'but nothing may be pinned for others'


# ── 3. a verification belongs to exactly one cluster ─────────────────────────

MINE, OTHER = 'cluster_1', 'cluster_2'


@pytest.fixture
def foreign_run(monkeypatch, api):
    """One in-flight verification, on the OTHER cluster."""
    row = {'id': 'task-x', 'cluster_id': OTHER, 'vmid': 200, 'status': 'running',
           'node': 'pve1', 'archive': 'vm/200/2026-09-06T02:00:00Z'}
    monkeypatch.setattr(bv, 'get_verification', lambda tid: row if tid == 'task-x' else None)
    for cid in (MINE, OTHER):
        api.set_manager(cid, api.make_fake_manager(cid))
    return row


def test_a_verification_from_another_cluster_is_not_readable_here(api, seed, foreign_run):
    """An unconfined operator on cluster_1 passes _verification_rows_visible unchanged,
    so the cluster match is the only thing standing between them and cluster_2's run."""
    seed.tenant('tenant_a', clusters=[MINE])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['vm.backup'])

    r = api.as_user(alice).get(f'/api/clusters/{MINE}/backup-verify/task-x')

    assert r.status_code == 404, r.get_data(as_text=True)[:200]
    assert 'vm/200' not in r.get_data(as_text=True)


def test_the_same_verification_reads_fine_on_its_own_cluster(api, seed, foreign_run):
    seed.tenant('tenant_b', clusters=[OTHER])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['vm.backup'])

    r = api.as_user(bob).get(f'/api/clusters/{OTHER}/backup-verify/task-x')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json()['vmid'] == 200
