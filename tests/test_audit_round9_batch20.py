# E2E for Batch 20 — the 31 write routes left over from the Batch-19 sweep, classified one by
# one instead of swept. Roughly half the value of this batch is in what it does NOT gate: the
# classification pass was checked in both directions, and the "too strong" direction rejected
# five proposals that would have 403'd callers who legitimately use those routes today.
#
# The rule that came out of it: a route whose permission is a BUILTIN ROLE_USER default
# (storage.upload / storage.download) never gets the confinement gate — confining it silently
# narrows a shipped role. vm.create is template-only but is the tenant_admin's core job, and its
# QEMU/LXC twins are consistent today, so that stays open too and goes to Nico as a pool-semantics
# question rather than a unilateral fix.
import time

import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _cluster(api, cid='cluster_1'):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    return api.set_manager(cid, m)


def _scoped(seed, name, perms):
    """Confined: reaches cluster_1 only through a pool grant (the #555 fallback)."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view', 'vm.config'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _owner(seed, name, perms):
    """Unconfined: cluster-wide operator in the tenant that OWNS the cluster."""
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user(name, role='user', tenant_id='acme', permissions=perms)


# ── whole-cluster infrastructure: confinement ────────────────────────────────
def test_scoped_caller_cannot_touch_the_datacenter_firewall(api, seed):
    u = _scoped(seed, 'fwmal', ['cluster.config', 'cluster.view'])
    _cluster(api)
    assert api.as_user(u).put('/api/clusters/cluster_1/datacenter/firewall/options',
                              json={'enable': 0}).status_code == 403
    assert api.as_user(u).post('/api/clusters/cluster_1/datacenter/firewall/rules',
                               json={'type': 'in', 'action': 'ACCEPT'}).status_code == 403


def test_scoped_caller_cannot_join_or_remove_a_node(api, seed):
    u = _scoped(seed, 'joinmal', ['cluster.admin', 'cluster.view'])
    _cluster(api)
    assert api.as_user(u).post('/api/clusters/cluster_1/nodes/join', json={}).status_code == 403
    assert api.as_user(u).delete(
        '/api/clusters/cluster_1/nodes/n1/cluster-membership').status_code == 403


def test_scoped_caller_cannot_write_storage_definitions(api, seed):
    u = _scoped(seed, 'stormal', ['storage.config', 'storage.delete', 'cluster.view'])
    _cluster(api)
    assert api.as_user(u).post('/api/clusters/cluster_1/datacenter/storage',
                               json={'storage': 'x', 'type': 'dir'}).status_code == 403
    assert api.as_user(u).delete(
        '/api/clusters/cluster_1/datacenter/storage/local').status_code == 403


def test_scoped_caller_cannot_connect_an_esxi_host(api, seed):
    u = _scoped(seed, 'esximal', ['cluster.admin', 'cluster.view'])
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/esxi-hosts',
                            json={'host': 'h', 'user': 'u', 'password': 'p'})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_owning_operator_keeps_the_infrastructure_routes(api, seed):
    # the guard must fire on confinement, not on the permission
    from pegaprox.api.helpers import require_unconfined
    u = _owner(seed, 'infraops', ['cluster.config', 'storage.config', 'cluster.view'])
    _cluster(api)
    with api.app.test_request_context('/'):
        from flask import request, g
        request.session = {'user': 'infraops', 'role': 'user'}
        g.current_user = u
        assert require_unconfined('cluster_1') is None


# ── replication job id carries the guest: per-VM, not confinement ────────────
def test_replication_job_delete_and_run_are_gated_on_the_guest(api, seed):
    u = _scoped(seed, 'repmal', ['cluster.config', 'cluster.view'])
    _cluster(api)
    # job id is "<vmid>-<jobnum>" — 300 is outside mallory's pool
    assert api.as_user(u).delete('/api/clusters/cluster_1/replication/300-0').status_code == 403
    assert api.as_user(u).post(
        '/api/clusters/cluster_1/replication/300-0/run', json={}).status_code == 403


def test_replication_job_for_an_own_guest_still_works(api, seed):
    u = _scoped(seed, 'repok', ['cluster.config', 'cluster.view'])
    m = _cluster(api)
    m.delete_replication_job.return_value = {'success': True}
    r = api.as_user(u).delete('/api/clusters/cluster_1/replication/100-0')
    assert r.status_code != 403, r.get_data(as_text=True)


def test_replication_job_with_a_malformed_id_fails_closed(api, seed):
    u = _scoped(seed, 'repbad', ['cluster.config', 'cluster.view'])
    _cluster(api)
    assert api.as_user(u).delete(
        '/api/clusters/cluster_1/replication/not-a-job').status_code == 403


# ── datastore content: the volid carries the guest ───────────────────────────
def _content_mgr(api):
    m = _cluster(api)
    m.host, m.api_port = '10.0.0.1', 8006
    return m


def test_scoped_caller_cannot_delete_a_foreign_guests_backup(api, seed):
    u = _scoped(seed, 'volmal', ['storage.delete', 'cluster.view'])
    _content_mgr(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/datastores/local/content/'
        'local:backup/vzdump-qemu-300-2026_01_01-00_00_00.vma.zst')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_scoped_caller_cannot_delete_a_foreign_guests_disk(api, seed):
    u = _scoped(seed, 'volmal2', ['storage.delete', 'cluster.view'])
    _content_mgr(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/datastores/local/content/local:vm-300-disk-0')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_scoped_caller_may_still_delete_shared_iso_content(api, seed):
    # ISO/vztmpl volids carry no vmid — routine housekeeping a scoped tenant admin does today.
    # Failing closed on an unparsable volid would break that, so the gate must not fire here.
    u = _scoped(seed, 'volok', ['storage.delete', 'cluster.view'])
    _content_mgr(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/datastores/local/content/local:iso/ubuntu.iso')
    assert r.status_code != 403, r.get_data(as_text=True)


def test_a_snippet_named_like_a_disk_is_not_attributed_to_that_guest(api, seed):
    # local:snippets/vm-300-cloudinit.yml must not be read as guest 300's disk
    u = _scoped(seed, 'volsnip', ['storage.delete', 'cluster.view'])
    _content_mgr(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/datastores/local/content/local:snippets/vm-300-cloudinit.yml')
    assert r.status_code != 403, r.get_data(as_text=True)


def test_unconfined_storage_admin_keeps_deleting_any_volume(api, seed):
    # storage_admin holds storage.delete but NEITHER vm.backup NOR vm.config. Gating on those
    # would 403 the role for every vmid-carrying volid — the exact job it exists for.
    u = _owner(seed, 'storageadmin', ['storage.delete', 'storage.view', 'cluster.view', 'vm.view'])
    _content_mgr(api)
    r = api.as_user(u).delete(
        '/api/clusters/cluster_1/datastores/local/content/'
        'local:backup/vzdump-qemu-300-2026_01_01-00_00_00.vma.zst')
    assert r.status_code != 403, r.get_data(as_text=True)


# ── routes deliberately left OPEN — these assert the absence of a regression ──
def test_pool_user_can_still_download_an_iso(api, seed):
    # storage.upload/storage.download are BUILTIN ROLE_USER perms. Confining these would 403 the
    # pool-scoped Client Portal user this whole audit exists to protect, for a self-service
    # workflow the UI already offers them.
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('pooluser', role='user', tenant_id='tenant_x',
                  permissions=['storage.upload', 'storage.download', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'pooluser', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    m = _content_mgr(api)
    m.download_url_to_storage.return_value = {'success': True}
    r = api.as_user(u).post('/api/clusters/cluster_1/datastores/local/download-url',
                            json={'url': 'https://example.com/x.iso', 'filename': 'x.iso'})
    assert r.status_code != 403, r.get_data(as_text=True)


def test_pool_scoped_tenant_admin_can_still_create_a_container(api, seed):
    # vm.create is the tenant_admin's core job, and the QEMU twin create_vm_api is equally
    # ungated — confining only the LXC path would be the asymmetry, not the fix.
    u = _scoped(seed, 'ctcreator', ['vm.create', 'cluster.view'])
    m = _cluster(api)
    m.create_container.return_value = {'success': True, 'vmid': 999}
    r = api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/lxc',
                            json={'vmid': 999, 'ostemplate': 'local:vztmpl/deb.tar.zst'})
    assert r.status_code != 403, r.get_data(as_text=True)


# ── storage-cluster delete mirrors its siblings, not require_unconfined ──────
def test_storage_cluster_delete_denies_a_foreign_tenant(api, seed):
    seed.tenant('other', clusters=['cluster_far'])
    u = seed.user('farmal', role='user', tenant_id='other',
                  permissions=['storage.config', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'farmal', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _cluster(api)
    r = api.as_user(u).delete('/api/clusters/cluster_1/storage-clusters/sc1')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_storage_cluster_delete_allows_the_owning_tenant_despite_a_pool_grant(api, seed):
    # this is why it is NOT require_unconfined: an owning-tenant admin who also holds a pool
    # grant must keep the delete, since create and update already let them through
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('ownadmin', role='user', tenant_id='acme',
                  permissions=['storage.config', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'ownadmin', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _cluster(api)
    r = api.as_user(u).delete('/api/clusters/cluster_1/storage-clusters/sc1')
    assert r.status_code != 403, r.get_data(as_text=True)
