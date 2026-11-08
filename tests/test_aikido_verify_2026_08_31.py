# Aikido ai_pentest re-verify batch (2026-08-31) — findings the adversarial pass confirmed still open.

from unittest.mock import MagicMock

_VMS = [
    {'vmid': 100, 'type': 'qemu', 'name': 'a', 'node': 'n1', 'status': 'running'},
    {'vmid': 200, 'type': 'qemu', 'name': 'b', 'node': 'n1', 'status': 'running'},
]


# 469089182 — GET /api/clusters/<id>/vms must filter per-VM, not dump the whole inventory to a
# user who only reaches the cluster via a VM-ACL / pool fallback.
def test_cluster_vms_list_filtered_for_acl_scoped_user(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['vm.view'])
    seed.vm_acl('cluster_1', 100, users=['bob'])          # bob is scoped to vmid 100 only
    fake = api.make_fake_manager('cluster_1', get_vm_resources=list(_VMS))
    fake.cluster_type = 'proxmox'
    api.set_manager('cluster_1', fake)
    resp = api.as_user(bob).get('/api/clusters/cluster_1/vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    got = sorted(v['vmid'] for v in resp.get_json()['vms'])
    assert got == [100], got   # only his ACL VM, NOT 200


def test_cluster_vms_list_admin_sees_all(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager('cluster_1', get_vm_resources=list(_VMS))
    fake.cluster_type = 'proxmox'
    api.set_manager('cluster_1', fake)
    resp = api.as_user(admin).get('/api/clusters/cluster_1/vms')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sorted(v['vmid'] for v in resp.get_json()['vms']) == [100, 200]


# 469089182 (sibling) — the adversarial verify showed /vms alone was not enough: the /resources
# endpoint returned the same inventory (a superset) to a pool-/ACL-reached user via the blanket
# role-level vm.view fallback. A caller who reaches the cluster only via an ACL/pool grant must be
# confined there too — while a tenant OWNER keeps the restrictive-ACL listing (other tests).
def test_cluster_resources_filtered_for_acl_reached_non_owner(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])   # tenant does NOT own cluster_1
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    seed.vm_acl('cluster_1', 100, users=['bob'])          # bob reaches cluster_1 only via this ACL
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=list(_VMS)))
    resp = api.as_user(bob).get('/api/clusters/cluster_1/resources')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    got = sorted(v['vmid'] for v in resp.get_json())
    assert got == [100], got   # only his ACL VM, NOT the whole inventory


# 469089255 CORE — build_authz_user must keep a token's tenant CUSTOM role NAME (not collapse it to
# a builtin), so its tenant scope resolves in get_user_clusters instead of falling back to the
# owner's default tenant and returning None = "all clusters".
def test_token_custom_role_name_is_preserved(seed):
    from pegaprox.utils.auth import build_authz_user
    seed.user('root', role='admin', tenant_id='default')
    # builtin viewer token still floors (regression guard)
    assert build_authz_user('root', {'user': 'root', 'role': 'viewer', 'api_token': True})['effective_role'] == 'viewer'
    # a custom-role token keeps the role NAME
    assert build_authz_user('root', {'user': 'root', 'role': 'auditor_t1', 'api_token': True})['effective_role'] == 'auditor_t1'
    # no token -> no effective_role (stored role applies)
    assert 'effective_role' not in build_authz_user('root', {'user': 'root', 'role': 'admin'})


def test_token_custom_role_scoped_to_role_tenant_not_all(seed, monkeypatch):
    from pegaprox.utils.rbac import get_user_clusters
    seed.tenant('tenant_t1', clusters=['cluster_a'])
    monkeypatch.setattr('pegaprox.utils.rbac.load_custom_roles',
                        lambda: {'global': {}, 'tenants': {'tenant_t1': {'auditor_t1': {'permissions': ['pbs.view']}}}})
    # admin-owned token floored to the tenant custom role — scoped to that role's tenant, NOT all
    u = {'role': 'admin', 'tenant_id': 'default', 'effective_role': 'auditor_t1'}
    assert get_user_clusters(u) == ['cluster_a']
    # counter: the OLD collapse-to-viewer behaviour returned None (all clusters)
    assert get_user_clusters({'role': 'admin', 'tenant_id': 'default', 'effective_role': 'viewer'}) is None


# 469089213 — POST /api/pbs/<id>/auto-storage injects the PBS's stored creds into a cluster's
# storage; a pool/ACL reach must NOT let a user target a cluster their tenant doesn't own.
def test_pbs_auto_attach_denied_target_not_tenant_owned(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['pbs.config'])
    seed.vm_acl('cluster_1', 100, users=['bob'])          # bob reaches cluster_1 only via ACL
    import pegaprox.globals as _g
    _g.pbs_managers['pbs1'] = MagicMock(linked_clusters=['cluster_1'], name='pbs1')
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    try:
        resp = api.as_user(bob).post('/api/pbs/pbs1/auto-storage',
                                     json={'clusters': ['cluster_1'], 'storage_name': 'x'})
        # denied at the tenant-ownership guard (before any fingerprint probe): 403 (or check_pbs_access 403)
        assert resp.status_code == 403, resp.get_data(as_text=True)
    finally:
        _g.pbs_managers.pop('pbs1', None)
