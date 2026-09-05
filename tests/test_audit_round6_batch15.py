# E2E for Batch 15 — Round-6. Two themes:
#   * the token-scope class from Batch 14 reaching further than vms.py (schedule list, token
#     management) plus the custom-role hole that let a token carry permissions its owner lacks;
#   * "the twin route forgot the gate" again — DR drills vs site-recovery plans, V2P vs XHM,
#     backup-job delete vs create, alert reads vs the alert list.
import time
import types
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed, name='mallory', perms=None):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x',
                  permissions=perms or ['cluster.view', 'vm.start', 'vm.stop'])
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view', 'vm.start', 'vm.stop'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _cluster(api, cid='cluster_1'):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    return api.set_manager(cid, m)


def _admin_token(seed, role='viewer', owner='root'):
    from pegaprox.utils.auth import create_api_token
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user(owner, role='admin', tenant_id='acme')
    res = create_api_token(owner, f'ci-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


# ── schedule hijack: PUT authorized only the NEW target ───────────────────────
def _seed_schedule(db, sid, cluster_id, vmid, owner='victim'):
    db.conn.execute(
        "INSERT INTO scheduled_actions (id, cluster_id, vmid, vm_type, action, schedule_type, "
        "schedule_time, enabled, name, created_by, created_at) "
        "VALUES (?, ?, ?, 'qemu', 'stop', 'daily', '02:00', 1, 'nightly', ?, '2026-01-01')",
        (sid, cluster_id, vmid, owner))
    db.conn.commit()


def test_schedule_put_cannot_hijack_a_foreign_schedule(api, seed, db):
    u = _pool_user(seed)
    _cluster(api)
    _seed_schedule(db, 7, 'cluster_1', 200)          # victim's VM, outside mallory's pool
    r = api.as_user(u).put('/api/schedules/7', json={'vmid': 100, 'action': 'start'})
    assert r.status_code == 403, r.get_data(as_text=True)
    # and the stored row must be untouched
    row = db.conn.execute('SELECT vmid, action FROM scheduled_actions WHERE id = 7').fetchone()
    assert (row[0], row[1]) == (200, 'stop')


def test_schedule_put_own_schedule_still_editable(api, seed, db):
    u = _pool_user(seed)
    _cluster(api)
    _seed_schedule(db, 8, 'cluster_1', 100, owner='mallory')
    r = api.as_user(u).put('/api/schedules/8', json={'action': 'start', 'time': '05:00'})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_schedule_put_cannot_retarget_onto_a_foreign_vm(api, seed, db):
    # the original Aug-2026 fix — still holds
    u = _pool_user(seed)
    _cluster(api)
    _seed_schedule(db, 9, 'cluster_1', 100, owner='mallory')
    r = api.as_user(u).put('/api/schedules/9', json={'vmid': 200})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_schedule_list_not_flooded_for_a_scoped_token(api, seed, db):
    hdr = _admin_token(seed)
    _cluster(api)
    _seed_schedule(db, 10, 'cluster_1', 100)
    _seed_schedule(db, 11, 'cluster_other', 300)
    body = api.anon().get('/api/schedules', headers=hdr).get_json()
    assert all(a['cluster_id'] != 'cluster_other' for a in body), body


# ── API-token management resolved admin.api off the owner's record ────────────
def test_scoped_token_cannot_enumerate_all_tokens(api, seed):
    from pegaprox.utils.auth import create_api_token
    hdr = _admin_token(seed)
    seed.user('someone', role='user', tenant_id='acme')
    create_api_token('someone', 'their-token', role='user')
    body = api.anon().get('/api/auth/tokens?all=true', headers=hdr).get_json()
    owners = {t.get('username') for t in body['tokens']}
    assert 'someone' not in owners, body


def test_scoped_token_cannot_revoke_another_users_token(api, seed):
    from pegaprox.utils.auth import create_api_token
    hdr = _admin_token(seed)
    seed.user('someone2', role='user', tenant_id='acme')
    victim = create_api_token('someone2', 'their-token', role='user')
    r = api.anon().delete(f"/api/auth/tokens/{victim['token_id']}", headers=hdr)
    assert r.status_code in (403, 404), r.get_data(as_text=True)


def test_admin_session_still_manages_all_tokens(api, seed):
    from pegaprox.utils.auth import create_api_token
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root9', role='admin', tenant_id='acme')
    seed.user('someone3', role='user', tenant_id='acme')
    create_api_token('someone3', 'their-token', role='user')
    body = api.as_user(admin).get('/api/auth/tokens?all=true').get_json()
    assert 'someone3' in {t.get('username') for t in body['tokens']}, body


# ── a token could be bound to a custom role its owner does not hold ───────────
def test_token_cannot_borrow_an_unheld_custom_role(seed, monkeypatch):
    from pegaprox.utils.auth import create_api_token
    import pegaprox.utils.rbac as rbacmod
    seed.user('bob', role='user', tenant_id='default')
    monkeypatch.setattr(rbacmod, 'get_custom_roles',
                        lambda: {'global': {'ops': {'permissions': ['vm.delete', 'node.update']}},
                                 'tenants': {}})
    res = create_api_token('bob', 'sneaky', role='ops')
    assert 'error' in res, res
    assert 'beyond your own role' in res['error']


def test_token_may_carry_a_custom_role_within_the_owners_perms(seed, monkeypatch):
    from pegaprox.utils.auth import create_api_token
    import pegaprox.utils.rbac as rbacmod
    seed.user('bob2', role='user', tenant_id='default')
    # a strictly-narrower custom role is still fine — this is the CI/CD use case
    monkeypatch.setattr(rbacmod, 'get_custom_roles',
                        lambda: {'global': {'readonly': {'permissions': ['vm.view']}}, 'tenants': {}})
    res = create_api_token('bob2', 'ci', role='readonly')
    assert res.get('success'), res


# ── V2P migrations: cluster reach was the whole gate (XHM's twin has more) ────
def _v2p_task(vmware_id='esxi1', vm_id='vm-999', target='cluster_1'):
    t = types.SimpleNamespace(vmware_id=vmware_id, vm_id=vm_id, target_cluster=target,
                              vm_name='finance-01', phase='awaiting_confirmation')
    t.to_dict = lambda: {'id': 'mig1', 'vm_name': 'finance-01', 'vmware_id': vmware_id,
                         'vm_id': vm_id, 'phase': 'awaiting_confirmation'}
    return t


def _v2p_env(api, seed):
    """mallory reaches the target cluster but has no grant on the ESXi server's VMs."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory3', role='user', tenant_id='tenant_x',
                  permissions=['cluster.view', 'vmware.vm.migrate'])
    _cluster(api)
    vm = MagicMock()
    vm.linked_clusters = ['cluster_foreign']      # the ESXi server belongs to another tenant
    ppglobals.vmware_managers['esxi1'] = vm
    from pegaprox.api import vmware as vmw_mod
    vmw_mod._vmware_migrations['mig1'] = _v2p_task()
    return u


def _v2p_cleanup():
    from pegaprox.api import vmware as vmw_mod
    vmw_mod._vmware_migrations.pop('mig1', None)
    ppglobals.vmware_managers.pop('esxi1', None)


def test_v2p_migration_detail_denied_without_source_vm_access(api, seed):
    u = _v2p_env(api, seed)
    try:
        assert api.as_user(u).get('/api/vmware/migrations/mig1').status_code == 404
        assert api.as_user(u).get('/api/vmware/migrations').get_json() == []
    finally:
        _v2p_cleanup()


def test_v2p_cutover_denied_without_source_vm_access(api, seed):
    # the sharp end: confirm/cancel drive another tenant's switchover
    u = _v2p_env(api, seed)
    try:
        assert api.as_user(u).post('/api/vmware/migrations/mig1/confirm-cutover').status_code == 404
        assert api.as_user(u).post('/api/vmware/migrations/mig1/cancel-cutover').status_code == 404
        from pegaprox.api import vmware as vmw_mod
        t = vmw_mod._vmware_migrations['mig1']
        assert not getattr(t, '_cutover_confirmed', False)
        assert not getattr(t, '_cutover_cancelled', False)
    finally:
        _v2p_cleanup()


def test_v2p_admin_still_sees_migrations(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root8', role='admin', tenant_id='acme')
    _cluster(api)
    vm = MagicMock()
    vm.linked_clusters = ['cluster_foreign']
    ppglobals.vmware_managers['esxi1'] = vm
    from pegaprox.api import vmware as vmw_mod
    vmw_mod._vmware_migrations['mig1'] = _v2p_task()
    try:
        assert api.as_user(admin).get('/api/vmware/migrations/mig1').status_code == 200
    finally:
        _v2p_cleanup()


# ── DR drills were a read path around the plan's per-VM gate ──────────────────
def _seed_plan(db, plan_id='plan_x', src='cluster_1', dst='cluster_1', vmids=(200, 201)):
    db.conn.execute(
        "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, "
        "pre_failover_webhook, post_failover_webhook, created_at) "
        "VALUES (?, 'g1', 'prod-dr', ?, ?, 'https://hooks.example/T0/SECRET', '', '2026-01-01')",
        (plan_id, src, dst))
    for i, v in enumerate(vmids):
        db.conn.execute(
            "INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type) "
            "VALUES (?, ?, ?, ?, 'qemu')", (f'{plan_id}-v{i}', plan_id, v, f'vm{v}'))
    db.conn.commit()


def test_dr_drill_detail_denied_for_a_scoped_caller(api, seed, db):
    u = _pool_user(seed, 'mallory4', perms=['cluster.view', 'site_recovery.view'])
    _cluster(api)
    _seed_plan(db)
    db.conn.execute(
        "INSERT INTO dr_drills (id, plan_id, plan_name, started_at, status, started_by) "
        "VALUES ('d1', 'plan_x', 'prod-dr', '2026-01-01', 'done', 'admin')")
    db.conn.commit()
    assert api.as_user(u).get('/api/dr-drills/d1').status_code == 404
    assert api.as_user(u).get('/api/site-recovery/plans/plan_x/drills').status_code == 404


def test_dr_drill_detail_allowed_when_the_plan_is_the_callers(api, seed, db):
    u = _pool_user(seed, 'mallory5', perms=['cluster.view', 'site_recovery.view'])
    _cluster(api)
    _seed_plan(db, 'plan_own', vmids=(100,))       # only VM 100 — mallory's pool
    db.conn.execute(
        "INSERT INTO dr_drills (id, plan_id, plan_name, started_at, status, started_by) "
        "VALUES ('d2', 'plan_own', 'own', '2026-01-01', 'done', 'admin')")
    db.conn.commit()
    assert api.as_user(u).get('/api/dr-drills/d2').status_code == 200


# ── plan list: no per-VM confinement, and it shipped the webhook secrets ──────
def test_plan_list_confines_and_strips_webhooks(api, seed, db):
    u = _pool_user(seed, 'mallory6', perms=['cluster.view', 'site_recovery.view'])
    _cluster(api)
    _seed_plan(db, 'plan_foreign', vmids=(200, 201))
    _seed_plan(db, 'plan_mine', vmids=(100,))
    body = api.as_user(u).get('/api/site-recovery/plans').get_json()
    assert [p['id'] for p in body] == ['plan_mine'], body
    assert 'pre_failover_webhook' not in body[0], "list view must not carry the webhook secret"


def test_plan_list_admin_sees_all(api, seed, db):
    seed.tenant('acme', clusters=['cluster_1'])
    admin = seed.user('root7', role='admin', tenant_id='acme')
    _cluster(api)
    _seed_plan(db, 'plan_a', vmids=(200,))
    _seed_plan(db, 'plan_b', vmids=(100,))
    body = api.as_user(admin).get('/api/site-recovery/plans').get_json()
    assert {p['id'] for p in body} == {'plan_a', 'plan_b'}, body


def test_add_vm_to_a_foreign_plan_denied(api, seed, db):
    u = _pool_user(seed, 'mallory7', perms=['cluster.view', 'site_recovery.manage'])
    _cluster(api)
    _seed_plan(db, 'plan_victim', vmids=(200, 201))
    r = api.as_user(u).post('/api/site-recovery/plans/plan_victim/vms', json={'vmid': 100})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── alert reads named VMs the caller may not see ──────────────────────────────
def test_active_alerts_scoped(api, seed, db):
    u = _pool_user(seed, 'mallory8', perms=['cluster.view'])
    _cluster(api)
    for aid, vmid, name in (('a1', '100', 'own-vm'), ('a2', '300', 'finance-db')):
        db.conn.execute(
            "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, "
            "target_id, target_name, severity, message, current_value, threshold, operator, "
            "triggered_at) VALUES (?, ?, ?, 'cluster_1', 'cpu', 'vm', ?, ?, 'warning', 'hot', "
            "91.0, 90.0, '>', '2026-01-01')", (aid, aid, aid, vmid, name))
    db.conn.commit()
    body = api.as_user(u).get('/api/clusters/cluster_1/active-alerts').get_json()
    names = [a['target_name'] for a in body['active_alerts']]
    assert names == ['own-vm'], body
    assert 'target_id' not in body['active_alerts'][0], "target_id is internal to the filter"


def test_cluster_alert_rules_scoped(api, seed, db, monkeypatch):
    u = _pool_user(seed, 'mallory9', perms=['cluster.view'])
    _cluster(api)
    import pegaprox.api.alerts as alerts_mod
    monkeypatch.setattr(alerts_mod, 'load_cluster_alerts', lambda: {'cluster_1': [
        {'id': 'r1', 'name': 'own', 'target_type': 'vm', 'target_id': '100'},
        {'id': 'r2', 'name': 'finance', 'target_type': 'vm', 'target_id': '300'},
        {'id': 'r3', 'name': 'node cpu', 'target_type': 'node', 'target_id': 'n1'},
    ]})
    body = api.as_user(u).get('/api/clusters/cluster_1/alerts').get_json()
    assert [a['id'] for a in body['alerts']] == ['r1', 'r3'], body


# ── webhook secrets behind ?full=1 ────────────────────────────────────────────
def test_alert_channels_full_requires_settings_admin(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('chanmgr', role='user', tenant_id='acme', permissions=['alert.manage'])
    import pegaprox.api.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, 'load_server_settings', lambda: {
        'alert_webhooks': [{'id': 'c1', 'name': 'ops',
                            'url': 'https://hooks.slack.com/services/T0/B0/VERYSECRETTOKENVALUE',
                            'token': 'abc'}]})
    r = api.as_user(u).get('/api/alert-channels?full=1')
    assert r.status_code == 403, r.get_data(as_text=True)
    # the masked view still works for them
    masked = api.as_user(u).get('/api/alert-channels').get_json()
    assert 'VERYSECRETTOKENVALUE' not in masked[0]['url']
    assert masked[0]['token'] == '********'


def test_alert_channels_full_allowed_for_settings_admin(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('root6', role='admin', tenant_id='acme')
    import pegaprox.api.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, 'load_server_settings', lambda: {
        'alert_webhooks': [{'id': 'c1', 'name': 'ops', 'url': 'https://hooks/x', 'token': 'abc'}]})
    r = api.as_user(u).get('/api/alert-channels?full=1')
    assert r.status_code == 200 and r.get_json()[0]['token'] == 'abc'


# ── affinity rules drive live migrations, so members need authorizing ─────────
def test_affinity_rule_cannot_name_foreign_vms(api, seed):
    u = _pool_user(seed, 'mallory10', perms=['cluster.view', 'cluster.config'])
    _cluster(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/affinity-rules',
                            json={'name': 'evict', 'type': 'separate', 'vm_ids': [300, 301]})
    assert r.status_code == 403, r.get_data(as_text=True)


# ── metrics scrape kept working for a disabled admin's token ──────────────────
def test_metrics_rejects_a_disabled_admins_token(api, seed, monkeypatch):
    seed.user('exadmin', role='admin', tenant_id='default', enabled=False)
    import pegaprox.api.metrics_exporter as mx
    monkeypatch.setattr(mx, 'validate_api_token', lambda tok: {'user': 'exadmin', 'role': 'admin'})
    r = api.anon().get('/api/metrics', headers={'Authorization': 'Bearer pgx_dummy'})
    assert r.status_code == 401, r.get_data(as_text=True)


def test_metrics_rejects_a_demoted_admins_token(api, seed, monkeypatch):
    seed.user('demoted', role='user', tenant_id='default')
    import pegaprox.api.metrics_exporter as mx
    monkeypatch.setattr(mx, 'validate_api_token', lambda tok: {'user': 'demoted', 'role': 'admin'})
    r = api.anon().get('/api/metrics', headers={'Authorization': 'Bearer pgx_dummy'})
    assert r.status_code == 401, r.get_data(as_text=True)


# ── migration / DR progress frames were broadcast globally, around the REST gates ──
import json as _json
import queue as _queue


def _register_sse(user, is_admin, clusters=None):
    q = _queue.Queue()
    cid = f'test-sse-{user}'
    with ppglobals.sse_clients_lock:
        ppglobals.sse_clients[cid] = {
            'queue': q, 'user': user, 'clusters': clusters, 'is_admin': is_admin,
            'connected_at': 'x', 'auth_method': 'test',
        }
    return q, cid


def _drain_sse(q):
    out = []
    try:
        while True:
            out.append(_json.loads(q.get_nowait()))
    except _queue.Empty:
        pass
    return out


def test_xhm_frame_not_broadcast_to_everyone(api, seed, db):
    from pegaprox.utils.realtime import broadcast_sse
    # the stream mirrors the REST gate exactly: _xhm_reachable asks for vm.migrate, so this
    # pool grant carries it — otherwise she legitimately can't see the migration either way
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('mallory11', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory11', ['pool.view', 'vm.view', 'vm.migrate'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    seed.user('rootsse', role='admin', tenant_id='acme')
    _cluster(api)
    ppglobals._xhm_migrations['x1'] = types.SimpleNamespace(
        source_cluster='cluster_1', source_vmid=300, vm_name='finance-db')
    mq, mcid = _register_sse('mallory11', False, ['cluster_1'])
    aq, acid = _register_sse('rootsse', True)
    try:
        broadcast_sse('xhm_migration', {'id': 'x1', 'vm_name': 'finance-db', 'phase': 'copy'})
        assert _drain_sse(mq) == [], "a pool user must not see a foreign VM's migration frame"
        assert len(_drain_sse(aq)) == 1, "admin still sees it"
        # ...and their own VM's migration still reaches them
        ppglobals._xhm_migrations['x2'] = types.SimpleNamespace(
            source_cluster='cluster_1', source_vmid=100, vm_name='mine')
        broadcast_sse('xhm_migration', {'id': 'x2', 'vm_name': 'mine', 'phase': 'copy'})
        assert len(_drain_sse(mq)) == 1
    finally:
        ppglobals._xhm_migrations.pop('x1', None)
        ppglobals._xhm_migrations.pop('x2', None)
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)
            ppglobals.sse_clients.pop(acid, None)


def test_site_recovery_frame_not_broadcast_to_everyone(api, seed, db):
    from pegaprox.utils.realtime import broadcast_sse
    u = _pool_user(seed, 'mallory12')
    _cluster(api)
    _seed_plan(db, 'plan_sse', vmids=(200,))
    mq, mcid = _register_sse('mallory12', False, ['cluster_1'])
    try:
        broadcast_sse('site_recovery', {'plan_id': 'plan_sse', 'message': 'failing over prod-db'})
        assert _drain_sse(mq) == [], "DR progress for a plan they can't open must not reach them"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)


def test_unresolvable_migration_frame_fails_closed(api, seed):
    from pegaprox.utils.realtime import broadcast_sse
    _pool_user(seed, 'mallory13')
    _cluster(api)
    mq, mcid = _register_sse('mallory13', False, ['cluster_1'])
    try:
        broadcast_sse('vmware_migration_log', {'id': 'gone', 'line': 'esxi-host-01 datastore ds1'})
        assert _drain_sse(mq) == [], "a frame we cannot resolve must not be delivered to a non-admin"
    finally:
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients.pop(mcid, None)
