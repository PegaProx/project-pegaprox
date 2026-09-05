# E2E for Batch 18 — Round-8. A whole class this time: operations that affect the ENTIRE cluster
# (rewriting its credentials, rebooting/draining nodes, arming fencing, wiping a disk) were gated
# on a role perm plus check_cluster_access — and check_cluster_access admits a pool-/ACL-scoped
# caller by design. There is no per-object question to ask about a node reboot, so the right gate
# is confinement: helpers.require_unconfined.
#
# What makes this reachable rather than theoretical: the SHIPPED tenant_admin role template grants
# cluster.config, ha.config, node.shell, node.network, node.maintenance and storage.config.
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


def _pool_scoped_tenant_admin(seed, name='mallory'):
    """The realistic attacker: a tenant_admin-shaped role whose only reach into this cluster is
    one pool grant, i.e. exactly what check_cluster_access's #555 fallback lets through."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x',
                  permissions=['cluster.config', 'ha.config', 'node.shell', 'node.network',
                               'node.maintenance', 'node.reboot', 'storage.config',
                               'cluster.view', 'node.view'])
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _plain_operator(seed, name='ops'):
    """A cluster-wide operator in the tenant that OWNS the cluster — must be unaffected."""
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user(name, role='user', tenant_id='acme',
                     permissions=['cluster.config', 'ha.config', 'node.network',
                                  'node.maintenance', 'node.reboot', 'storage.config',
                                  'cluster.view', 'node.view'])


# ── the sharpest one: rewriting the cluster's host redirects its stored credentials ──
def test_scoped_caller_cannot_repoint_the_cluster_host(api, seed):
    # host/user/ssl_verification/fallback_hosts are all in ALLOWED_CONFIG_FIELDS, and the manager
    # presents the STORED root password to config.host on the next auth — so this is credential
    # exfiltration, not just a config edit.
    u = _pool_scoped_tenant_admin(seed)
    m = _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1',
                           json={'host': 'attacker.example', 'ssl_verification': False})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert m.config.host != 'attacker.example', "the write must not have landed"


def test_scoped_caller_cannot_set_fallback_hosts(api, seed):
    # same primitive by another door — fallback_hosts feeds the same hosts_to_try list
    u = _pool_scoped_tenant_admin(seed, 'mallory2')
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/fallback-hosts',
                           json={'fallback_hosts': ['attacker.example']})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_scoped_caller_cannot_rotate_the_cluster_api_token(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory3')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/api-token/rotate', json={})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_owning_operator_can_still_edit_cluster_config(api, seed):
    u = _plain_operator(seed)
    m = _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1', json={'migration_threshold': 80})
    assert r.status_code == 200, r.get_data(as_text=True)


# ── fencing: arming or disarming it is a cluster-wide availability lever ──────
def test_scoped_caller_cannot_touch_ha_config(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory4')
    _cluster(api)
    assert api.as_user(u).put('/api/clusters/cluster_1/ha/config',
                              json={'strict_fencing': False}).status_code == 403
    assert api.as_user(u).post('/api/clusters/cluster_1/ha/disable', json={}).status_code == 403


# ── node reboot / drain ──────────────────────────────────────────────────────
def test_scoped_caller_cannot_drain_or_reboot_a_node(api, seed):
    # drain live-migrates EVERY VM off the node, including other tenants'
    u = _pool_scoped_tenant_admin(seed, 'mallory5')
    _cluster(api)
    assert api.as_user(u).put('/api/clusters/cluster_1/nodes/n1/maintenance',
                              json={'enabled': True}).status_code == 403
    assert api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/action/reboot',
                               json={}).status_code == 403


def test_owning_operator_is_not_confined(api, seed):
    # the guard must fire only for a CONFINED caller — a cluster-wide operator in the owning
    # tenant passes it (asserted on a route with a simple response shape)
    from pegaprox.api.helpers import require_unconfined
    from pegaprox.utils.auth import create_session
    u = _plain_operator(seed, 'ops2')
    _cluster(api)
    with api.app.test_request_context('/'):
        from flask import request, g
        request.session = {'user': 'ops2', 'role': 'user'}
        g.current_user = u
        assert require_unconfined('cluster_1') is None, "an owning operator must not be confined"
        request.session = {'user': 'mallory', 'role': 'viewer'}
        g.current_user = None


# ── datacenter options: migration_unsecure puts co-tenant VM memory on the wire ──
def test_scoped_caller_cannot_set_datacenter_options(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory6')
    _cluster(api)
    r = api.as_user(u).put('/api/clusters/cluster_1/datacenter/options',
                           json={'migration_unsecure': 1})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── node network + certificate rewrites ──────────────────────────────────────
def test_scoped_caller_cannot_rewrite_node_network(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory7')
    _cluster(api)
    # PUT /network is the apply, DELETE /network the revert
    assert api.as_user(u).put('/api/clusters/cluster_1/nodes/n1/network',
                              json={}).status_code == 403
    assert api.as_user(u).put('/api/clusters/cluster_1/nodes/n1/dns',
                              json={'dns1': '1.2.3.4'}).status_code == 403


# ── disk wipe ────────────────────────────────────────────────────────────────
def test_scoped_caller_cannot_wipe_a_node_disk(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory8')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/disks/wipe',
                            json={'disk': '/dev/sdb', 'confirm_name': '/dev/sdb'})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── node hardening can lock PegaProx out of the cluster ──────────────────────
def test_scoped_caller_cannot_apply_node_hardening(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory9')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/nodes/n1/hardening',
                            json={'controls': ['sshd_hardening'], 'force': True})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── balance-now: the guard was there but asked the wrong question ────────────
def test_balance_now_guard_is_not_bypassable_by_a_pool_grant(api, seed):
    # the old check was `get_user_clusters(...)` which defaults to include_pools=True, so the
    # pool-scoped caller's cluster WAS in the allowed set and the guard passed
    u = _pool_scoped_tenant_admin(seed, 'mallory10')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/balance-now', json={})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── writes that DO have a per-object notion get a per-VM gate, not confinement ──
def test_replication_job_cannot_target_a_foreign_vm(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory11')
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/replication',
                            json={'vmid': 300, 'target': 'n2'})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_replication_job_for_an_own_vm_is_allowed(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory12', role='viewer', tenant_id='tenant_x',
                  permissions=['cluster.config', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory12', ['pool.view', 'vm.view', 'vm.config'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    m = _cluster(api)
    m.create_replication_job.return_value = {'success': True}
    r = api.as_user(u).post('/api/clusters/cluster_1/replication',
                            json={'vmid': 100, 'target': 'n2'})
    assert r.status_code != 403, r.get_data(as_text=True)


def test_excluded_vm_write_cannot_target_a_foreign_vm(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory13')
    _cluster(api)
    assert api.as_user(u).post('/api/clusters/cluster_1/excluded-vms/300',
                               json={}).status_code == 403
    assert api.as_user(u).delete('/api/clusters/cluster_1/excluded-vms/300').status_code == 403


# ── HA membership is a per-VM availability lever ─────────────────────────────
def test_ha_membership_cannot_target_a_foreign_vm(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory14')
    _cluster(api)
    assert api.as_user(u).post('/api/clusters/cluster_1/proxmox-ha/resources',
                               json={'sid': 'vm:300'}).status_code == 403
    assert api.as_user(u).delete(
        '/api/clusters/cluster_1/proxmox-ha/resources/vm:300').status_code == 403


def test_ha_resource_listing_is_scoped(api, seed):
    u = _pool_scoped_tenant_admin(seed, 'mallory15')
    m = _cluster(api)
    m.get_proxmox_ha_resources.return_value = [
        {'sid': 'vm:100', 'state': 'started'},
        {'sid': 'vm:300', 'state': 'started'},
    ]
    body = api.as_user(u).get('/api/clusters/cluster_1/proxmox-ha/resources').get_json()
    assert [r['sid'] for r in body] == ['vm:100'], body


# ── a "secrets excluded" backup must not carry the cluster root password ─────
def test_backup_secret_sweep_strips_the_cluster_password():
    from pegaprox.api.settings import _strip_secret_fields
    # 'pass' is the key get_all_clusters decrypts the ROOT PASSWORD into, and 'password' is not
    # a substring of it — the marker sweep alone shipped it in a "no secrets" archive
    c = {'id': 'c1', 'host': 'h', 'user': 'root@pam', 'pass': 'ROOTPASSWORD',
         'ssh_key': 'KEY', 'api_token_secret': 'TOK', 'api_token_name': 'keep-me'}
    _strip_secret_fields(c)
    assert 'pass' not in c and 'ssh_key' not in c and 'api_token_secret' not in c, c
    assert c['api_token_name'] == 'keep-me' and c['host'] == 'h'
