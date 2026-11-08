# Regression guards for the third Aikido code-audit remediation pass (NS Aug 2026).
#
#   * #469089241 — GET /api/power/rates listed EVERY cluster's rates to any authed user
#     (cross-tenant info disclosure). It must now scope rows to the caller's reachable
#     clusters while always keeping the shared '__default__' fallback row.
#   * #469089251 — the client portal gated a REBOOT (stop+start, service-interrupting) on
#     vm.start. It must gate on vm.restart, the dedicated perm the main API/scheduler use,
#     so a vm.start-only portal user can no longer reboot a guest.


# ---------------------------------------------------------------------------
# #469089241 — power-rate list is scoped to the caller's clusters
# ---------------------------------------------------------------------------

def _seed_rate(seed, cluster_id):
    # rest of the columns have table defaults; we only need the row to exist.
    seed.db.execute(
        "INSERT OR REPLACE INTO power_rates (cluster_id, kwh_price, updated_at) VALUES (?, ?, ?)",
        (cluster_id, 0.42, '2026-01-01T00:00:00'))


def test_list_power_rates_scoped_to_caller_clusters(api, seed):
    _seed_rate(seed, 'cluster_a')
    _seed_rate(seed, 'cluster_b')
    seed.tenant('tenant_a', clusters=['cluster_a'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')

    r = api.as_user(alice).get('/api/power/rates')
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = {row['cluster_id'] for row in r.get_json()['rates']}

    assert 'cluster_a' in ids            # her own cluster
    assert '__default__' in ids          # shared fallback row is always kept
    assert 'cluster_b' not in ids        # another tenant's cluster must be hidden


def test_list_power_rates_admin_sees_all(api, seed):
    _seed_rate(seed, 'cluster_a')
    _seed_rate(seed, 'cluster_b')
    root = seed.user('root', role='admin', tenant_id='default')

    r = api.as_user(root).get('/api/power/rates')
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = {row['cluster_id'] for row in r.get_json()['rates']}
    assert {'cluster_a', 'cluster_b', '__default__'} <= ids


# ---------------------------------------------------------------------------
# cost rates — same IDOR class as power rates (GET /api/cost/rates + /<id>)
# ---------------------------------------------------------------------------

def _seed_cost_rate(seed, cluster_id):
    seed.db.execute(
        "INSERT OR REPLACE INTO cost_rates (cluster_id, cpu_per_core_h, updated_at) VALUES (?, ?, ?)",
        (cluster_id, 0.02, '2026-01-01T00:00:00'))


def test_list_cost_rates_scoped_to_caller_clusters(api, seed):
    _seed_cost_rate(seed, 'cluster_a')
    _seed_cost_rate(seed, 'cluster_b')
    seed.tenant('tenant_a', clusters=['cluster_a'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')

    r = api.as_user(alice).get('/api/cost/rates')
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = {row['cluster_id'] for row in r.get_json()['rates']}
    assert 'cluster_a' in ids
    assert '__default__' in ids
    assert 'cluster_b' not in ids


def test_get_one_cost_rate_denies_foreign_cluster(api, seed):
    _seed_cost_rate(seed, 'cluster_b')
    seed.tenant('tenant_a', clusters=['cluster_a'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    r = api.as_user(alice).get('/api/cost/rates/cluster_b')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_get_default_cost_rate_allowed_for_any_user(api, seed):
    # the shared __default__ pseudo-cluster is readable by anyone (no owner).
    seed.tenant('tenant_a', clusters=['cluster_a'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    r = api.as_user(alice).get('/api/cost/rates/__default__')
    assert r.status_code == 200, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# #469089251 — portal reboot gates on vm.restart, not vm.start
# ---------------------------------------------------------------------------

_ALL_ACTIONS = ['vm.view', 'vm.start', 'vm.stop', 'vm.console', 'vm.restart']


def _run_portal_power(monkeypatch, action, user_perms, allowed_actions):
    """Drive the portal _vm_power handler with the RBAC + config layers faked.
    Returns (result_dict, perm_the_VM_ACL_was_checked_with)."""
    import plugins.client_portal as portal

    captured = {}

    def fake_access(user, cluster_id, vmid, perm):
        captured['perm'] = perm
        return False  # deny right after capture so no real manager is touched

    monkeypatch.setattr(portal, 'user_can_access_vm', fake_access)
    monkeypatch.setattr(portal, '_load_config', lambda: {'allowed_actions': allowed_actions})
    monkeypatch.setattr('pegaprox.utils.auth.build_authz_user',
                        lambda username, session: {'user': username, 'permissions': user_perms})

    from flask import Flask, request
    app = Flask(__name__)
    with app.test_request_context(json={'cluster_id': 'c1', 'vmid': 100, 'action': action}):
        request.session = {'user': 'alice'}
        res = portal._vm_power()
    return res, captured.get('perm')


def test_portal_reboot_gates_on_vm_restart(monkeypatch):
    res, perm = _run_portal_power(
        monkeypatch, 'reboot', user_perms=['vm.view', 'vm.start'], allowed_actions=_ALL_ACTIONS)
    assert perm == 'vm.restart'                    # the whole point — not vm.start
    assert res == {'error': 'Permission denied'}   # a vm.start-only user is refused


def test_portal_start_still_gates_on_vm_start(monkeypatch):
    # fence: the fix must not disturb the other actions.
    _res, perm = _run_portal_power(
        monkeypatch, 'start', user_perms=['vm.view'], allowed_actions=_ALL_ACTIONS)
    assert perm == 'vm.start'


def test_portal_shutdown_still_gates_on_vm_stop(monkeypatch):
    _res, perm = _run_portal_power(
        monkeypatch, 'shutdown', user_perms=['vm.view'], allowed_actions=_ALL_ACTIONS)
    assert perm == 'vm.stop'
