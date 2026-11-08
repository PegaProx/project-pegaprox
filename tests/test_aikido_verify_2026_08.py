# Regression suite for the 3 genuinely-open findings from the 2026-08-18 Aikido dashboard re-verify:
#   469089267 (HIGH) — PBS update reuses a preserved/masked credential across a host change (cred exfil)
#   469089250 (Med)  — /balance-now triggers cluster-wide migration reachable via ACL/pool fallback
#   469089261 (Med)  — auto_balance storage-cluster config armable via ACL/pool fallback
# The other 26 dashboard findings verified as already-fixed (stale), deferred (#491 token-scope), or
# do-not-harden (OIDC).

from unittest.mock import MagicMock

import pegaprox.globals as ppglobals


# ---------------------------------------------------------------------------
# 469089267 — PBS masked-password credential-exfil guard (fail closed on host change)
# ---------------------------------------------------------------------------

def _inject_pbs_mgr(pbs_id, host, linked_clusters):
    m = MagicMock()
    m.host = host
    m.port = 8007
    m.password = 'REAL-SECRET'
    m.api_token_secret = ''
    m.ssh_key = ''
    m.linked_clusters = linked_clusters
    m.name = pbs_id
    m.to_dict = lambda: {'id': pbs_id, 'name': pbs_id, 'host': host, 'linked_clusters': linked_clusters}
    ppglobals.pbs_managers[pbs_id] = m
    return m


def test_pbs_update_host_change_with_masked_password_is_rejected(api, seed):
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs_mgr('p1', 'good-pbs.example', ['cluster_1'])
    try:
        # move the PBS to an attacker host while submitting the masked password → must fail closed,
        # so the real stored secret is never persisted/sent to the new host
        r = api.as_user(root).put('/api/pbs/p1', json={'host': 'attacker.tld', 'password': '********'})
        assert r.status_code == 400, r.get_data(as_text=True)
        assert 're-enter' in r.get_data(as_text=True).lower()
        # the in-memory manager still points at the original host (nothing was saved)
        assert ppglobals.pbs_managers['p1'].host == 'good-pbs.example'
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_update_host_change_with_masked_ssh_key_is_rejected(api, seed):
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs_mgr('p1', 'good-pbs.example', ['cluster_1'])
    try:
        r = api.as_user(root).put('/api/pbs/p1', json={'host': 'attacker.tld', 'ssh_key': '********'})
        assert r.status_code == 400, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_update_masked_password_without_host_change_is_not_rejected(api, seed, monkeypatch):
    # control: host unchanged + masked password must NOT trip the cred-exfil guard (no over-block).
    # Stub save + manager rebuild so the test doesn't do real DB/connect work.
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs_mgr('p1', 'good-pbs.example', ['cluster_1'])
    import pegaprox.api.pbs as pbsmod
    monkeypatch.setattr(pbsmod, 'save_pbs_server', lambda *a, **k: None)
    fake_mgr = MagicMock(); fake_mgr.to_dict = lambda: {'id': 'p1'}; fake_mgr.connect = lambda: True
    monkeypatch.setattr(pbsmod, 'PBSManager', lambda *a, **k: fake_mgr)
    try:
        r = api.as_user(root).put('/api/pbs/p1', json={'host': 'good-pbs.example', 'password': '********', 'name': 'p1'})
        assert r.status_code != 400, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_update_malformed_port_is_rejected_not_500(api, seed):
    # CodeAnt (2026-08-19 daily scan) — a non-numeric port used to raise an unhandled ValueError
    # inside host/port change-detection (500). It must be rejected as a clean 400 instead.
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs_mgr('p1', 'good-pbs.example', ['cluster_1'])
    try:
        r = api.as_user(root).put('/api/pbs/p1', json={'port': 'not-a-number'})
        assert r.status_code == 400, r.get_data(as_text=True)
        assert 'port' in r.get_data(as_text=True).lower()
        # nothing was persisted on the bad-input path
        assert ppglobals.pbs_managers['p1'].host == 'good-pbs.example'
    finally:
        ppglobals.pbs_managers.clear()


# ---------------------------------------------------------------------------
# 469089250 — /balance-now confined to tenant-owned clusters
# ---------------------------------------------------------------------------

def test_balance_now_denied_when_cluster_reached_via_acl_fallback(api, seed):
    # tenant_b does NOT own cluster_1; bob only reaches it via a single VM-ACL → check_cluster_access
    # passes via the #248 fallback, but balance-now (cluster-wide migration) must be denied.
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['cluster.config'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user(bob).post('/api/clusters/cluster_1/balance-now')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_balance_now_allowed_for_tenant_owned_cluster(api, seed):
    # bob's tenant OWNS cluster_1 → allowed (not over-blocked). Stub run_balance_check.
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['cluster.config'])
    fake = api.make_fake_manager('cluster_1'); fake.is_connected = True
    fake.config = MagicMock(); fake.config.name = 'cluster_1'
    fake.run_balance_check = lambda **k: None
    api.set_manager('cluster_1', fake)
    r = api.as_user(bob).post('/api/clusters/cluster_1/balance-now')
    assert r.status_code == 200, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# 469089261 — auto_balance storage-cluster config confined to tenant-owned clusters
# ---------------------------------------------------------------------------

def test_storage_cluster_create_denied_via_acl_fallback(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['storage.config'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user(bob).post('/api/clusters/cluster_1/storage-clusters', json={
        'name': 'sc1', 'storages': ['local', 'ceph'], 'auto_balance': True})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_storage_cluster_create_allowed_for_tenant_owned(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['storage.config'])
    fake = api.make_fake_manager('cluster_1'); fake.config = MagicMock(); fake.config.name = 'cluster_1'
    api.set_manager('cluster_1', fake)
    r = api.as_user(bob).post('/api/clusters/cluster_1/storage-clusters', json={
        'name': 'sc1', 'storages': ['local', 'ceph'], 'auto_balance': True})
    assert r.status_code in (200, 201), r.get_data(as_text=True)


def test_storage_cluster_create_denied_via_pool_fallback(api, seed):
    # 469089261 re-verify (Aug-31): the arming guard called get_user_clusters() with the DEFAULT
    # include_pools=True, which re-added #555 pool-reached clusters and defeated the tenant-ownership
    # check — a storage.config holder with only a pool grant on the cluster could still arm the
    # userless cluster-wide balance worker. Fixed by include_pools=False; bob reaches cluster_1 ONLY
    # via a pool grant (his tenant owns cluster_other), so arming must be denied.
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['storage.config'])
    seed.pool('cluster_1', 'pool_1', 'bob', ['pool.view', 'vm.view'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user(bob).post('/api/clusters/cluster_1/storage-clusters', json={
        'name': 'sc1', 'storages': ['local', 'ceph'], 'auto_balance': True})
    assert r.status_code == 403, r.get_data(as_text=True)
