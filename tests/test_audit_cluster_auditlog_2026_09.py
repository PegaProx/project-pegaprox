# E2E for the Round-3 audit finding: GET /api/clusters/<id>/audit returned the whole cluster audit
# trail (every co-tenant's usernames, source IPs, VM ids, actions) to any cluster-reaching cluster.view
# holder. A pool-/ACL-scoped caller is now confined to entries about VMs they can access; admins and
# plain cluster-wide operators keep the full log.
import time

import pegaprox.utils.rbac as rbac
from pegaprox.utils.audit import log_audit

_CN = 'Cluster One'


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _seed_entries():
    log_audit('op', 'vm.start', 'Started VM 100', cluster=_CN)     # accessible to the pool user
    log_audit('op', 'vm.start', 'Started VM 999', cluster=_CN)     # foreign
    log_audit('op', 'user.login', 'Login from 10.0.0.9', cluster=_CN)  # no vmid → co-tenant metadata


def _mgr(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.config.name = _CN
    return m


def test_audit_log_pool_user_confined(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    api.set_manager('cluster_1', _mgr(api))
    _seed_entries()
    body = api.as_user(u).get('/api/clusters/cluster_1/audit').get_json()
    details = ' | '.join(e.get('details', '') for e in body)
    assert 'VM 100' in details, f"pool user should see their own VM's audit entry; got {details!r}"
    assert 'VM 999' not in details, "pool user must NOT see a foreign VM's audit entry"
    assert 'Login from' not in details, "pool user must NOT see non-VM (co-tenant) audit entries"


def test_audit_log_admin_full(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _mgr(api))
    _seed_entries()
    body = api.as_user(admin).get('/api/clusters/cluster_1/audit').get_json()
    details = ' | '.join(e.get('details', '') for e in body)
    assert 'VM 100' in details and 'VM 999' in details and 'Login from' in details, "admin sees the full log"


def test_audit_log_plain_operator_full(api, seed):
    seed.tenant('tenant_y', clusters=['cluster_1'])
    otto = seed.user('otto', role='viewer', tenant_id='tenant_y', permissions=['cluster.view'])
    rbac.tenants_db = {}
    api.set_manager('cluster_1', _mgr(api))
    _seed_entries()
    body = api.as_user(otto).get('/api/clusters/cluster_1/audit').get_json()
    details = ' | '.join(e.get('details', '') for e in body)
    assert 'VM 999' in details and 'Login from' in details, "plain operator keeps the full cluster log"
