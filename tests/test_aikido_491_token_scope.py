# #491 token-scope batch — propagate the API token's effective_role into the cluster/search/vmware
# authorization paths so an admin-owned token restricted to viewer/user can't inherit the owner's
# all-cluster / admin access. Closes the 3 deferred Aikido findings:
#   469089234 (helpers.check_cluster_access), 469089194 (search.py), 469089256 (vmware.py callers).

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import get_user_clusters, user_can_access_vmware_vm
from pegaprox.utils.auth import build_authz_user
from pegaprox.api.helpers import check_cluster_access


# ---------------------------------------------------------------------------
# root cause: get_user_clusters must honor effective_role (shared by 234 + 194)
# ---------------------------------------------------------------------------

def test_get_user_clusters_honors_effective_role(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    # real admin session (no token) → all clusters
    assert get_user_clusters({'role': 'admin', 'tenant_id': 'acme'}) is None
    # admin-owned token floored to viewer → confined to the tenant's clusters, NOT all
    scoped = get_user_clusters({'role': 'admin', 'tenant_id': 'acme', 'effective_role': 'viewer'})
    assert scoped is not None and scoped == ['cluster_1']


def test_get_user_clusters_plain_session_unchanged(seed):
    # no effective_role → behaves exactly as before (regression guard)
    seed.tenant('acme', clusters=['cluster_1'])
    assert get_user_clusters({'role': 'admin', 'tenant_id': 'acme'}) is None
    assert get_user_clusters({'role': 'user', 'tenant_id': 'acme'}) == ['cluster_1']


# ---------------------------------------------------------------------------
# 469089234 — check_cluster_access applies the token effective_role
# ---------------------------------------------------------------------------

def test_check_cluster_access_confines_admin_owned_viewer_token(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_other'])
    seed.user('root', role='admin', tenant_id='acme')
    with api.app.test_request_context('/'):
        from flask import request, g
        # admin-owned API token, floored to viewer
        request.session = {'user': 'root', 'role': 'viewer', 'api_token': True}
        g.current_user = {'role': 'admin', 'tenant_id': 'acme'}
        # own-tenant cluster still reachable
        ok, _ = check_cluster_access('cluster_1')
        assert ok is True
        # a cluster outside the token's scope must NOT be reachable (was: admin bypass → all)
        ok2, err2 = check_cluster_access('cluster_other')
        assert ok2 is False


def test_check_cluster_access_real_admin_still_all(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_other'])
    seed.user('root', role='admin', tenant_id='acme')
    with api.app.test_request_context('/'):
        from flask import request, g
        request.session = {'user': 'root', 'role': 'admin'}   # no token flag
        g.current_user = {'role': 'admin', 'tenant_id': 'acme'}
        ok, _ = check_cluster_access('cluster_other')
        assert ok is True   # real admin keeps all-cluster access (no over-block)


# ---------------------------------------------------------------------------
# 469089256 — vmware VM authz honors the token effective_role via build_authz_user
# ---------------------------------------------------------------------------

def test_vmware_admin_owned_viewer_token_confined(seed):
    seed.user('root', role='admin', tenant_id='default')
    seed.db.save_vm_acl('vmware:esxi-1', '100', {'users': ['root'], 'inherit_role': True, 'permissions': []})
    rbac.invalidate_vm_acls_cache()

    # real admin token/session → admin short-circuit → reaches any VMware VM
    admin_user = build_authz_user('root', {'user': 'root', 'role': 'admin'})
    assert user_can_access_vmware_vm(admin_user, 'esxi-1', '200', 'vmware.vm.view') is True

    # admin-owned token floored to viewer → NO admin short-circuit → confined to the ACL'd VM 100
    tok_user = build_authz_user('root', {'user': 'root', 'role': 'viewer', 'api_token': True})
    assert tok_user['effective_role'] == 'viewer'
    assert user_can_access_vmware_vm(tok_user, 'esxi-1', '100', 'vmware.vm.view') is True    # granted
    assert user_can_access_vmware_vm(tok_user, 'esxi-1', '200', 'vmware.vm.view') is False   # scoped away
