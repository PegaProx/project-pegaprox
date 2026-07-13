# Phase 3 smoke test — proves the full-stack integration harness works end-to-end
# BEFORE the per-blueprint suites are fanned out against it.
#
# It drives the REAL Flask app (create_app) + the REAL vms blueprint, faking only
# the cluster manager. The four authz cases below each traverse require_auth ->
# check_cluster_access -> the 404 gate -> _require_vm_access -> the manager, so they
# assert the SAME decision a browser or attacker would get — the thing the direct
# RBAC unit tests structurally cannot (that gap is what made the 2026-07-12 "BOLA"
# framing wrong).

CFG_ROUTE = '/api/clusters/cluster_1/vms/pve1/qemu/100/config'   # -> _get_vm_config_response


def _cfg_manager(api):
    """A fake manager whose get_vm_config succeeds — the allow-path shape."""
    return api.make_fake_manager(
        cluster_id='cluster_1',
        get_vm_config={'success': True, 'config': {'name': 'web01', 'cores': 4,
                                                   'memory': 8192, 'tags': 'prod'}},
    )


# ---------------------------------------------------------------------------
# unauthenticated
# ---------------------------------------------------------------------------

def test_anon_request_is_401(api, seed):
    api.set_manager('cluster_1', _cfg_manager(api))
    resp = api.anon().get(CFG_ROUTE)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# allow path — an admin reaches the manager and gets the config back
# ---------------------------------------------------------------------------

def test_admin_reads_vm_config_200(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.set_manager('cluster_1', _cfg_manager(api))

    resp = api.as_user(admin).get(CFG_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['name'] == 'web01'
    assert body['cores'] == 4


# ---------------------------------------------------------------------------
# deny path A — VM-level: a user who reaches the CLUSTER only via a pool grant
# must still be denied a VM that isn't in that grant (the rbac.py:853 reach guard).
# This is the case the direct unit test pins — here it's proven through HTTP.
# ---------------------------------------------------------------------------

def test_pool_reach_user_denied_at_vm_level_403(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_home'])   # does NOT own cluster_1
    alice = seed.user('alice', role='user', tenant_id='tenant_a')
    seed.pool('cluster_1', 'pool_1', 'alice', ['pool.view', 'vm.view'])  # reaches cluster_1
    api.set_manager('cluster_1', _cfg_manager(api))

    # alice passes check_cluster_access (pool) but VM 100 is outside her pool grant
    # and outside her tenant's clusters -> _require_vm_access denies.
    resp = api.as_user(alice).get(CFG_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    # and the manager was never consulted (deny fires before mgr.get_vm_config)
    api_mgr = __import__('pegaprox.globals', fromlist=['cluster_managers']).cluster_managers['cluster_1']
    api_mgr.get_vm_config.assert_not_called()


# ---------------------------------------------------------------------------
# deny path B — cluster-level: a cross-tenant user is denied before the VM check.
# ---------------------------------------------------------------------------

def test_cross_tenant_user_denied_at_cluster_level_403(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_2'])      # owns cluster_2, not cluster_1
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    api.set_manager('cluster_1', _cfg_manager(api))

    resp = api.as_user(bob).get(CFG_ROUTE)
    assert resp.status_code == 403, resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# CSRF plumbing — the harness's write path. A state-changing request WITHOUT the
# same-origin/XHR proof is rejected by the CSRF gate even when authenticated;
# the harness's own post() (which adds those headers) sails past it.
# ---------------------------------------------------------------------------

_WRITE_PROBE = '/api/clusters/cluster_1/vms/pve1/qemu/100/__integration_write_probe__'


def _csrf_blocked(resp):
    if resp.status_code != 403:
        return False
    return (resp.get_json(silent=True) or {}).get('error') == 'CSRF validation failed'


def test_authed_write_without_csrf_headers_is_blocked(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    sid = api.as_user(admin).session_id
    raw = api.app.test_client()
    # authenticated (session header) but NO Origin / X-Requested-With
    resp = raw.post(_WRITE_PROBE, json={}, headers={'X-Session-ID': sid},
                    base_url='http://localhost')
    assert _csrf_blocked(resp) is True


def test_harness_write_path_passes_csrf(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # api.post() adds Origin + X-Requested-With -> CSRF passes -> route not found (404),
    # proving it's the routing layer, not the CSRF gate, that stops it.
    resp = api.as_user(admin).post(_WRITE_PROBE, json={})
    assert _csrf_blocked(resp) is False
    assert resp.status_code == 404
