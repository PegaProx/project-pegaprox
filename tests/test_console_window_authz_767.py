"""#767 moved the console behind a URL anyone can type. What still gates it?

The in-app path used to be the gate by construction: you only got a console button
for a guest that was already on your screen. A console window is a plain link, so
the whole decision now sits server-side, and these drive the two endpoints a
console window actually calls — the VNC ticket and the LXC termproxy ticket — as
identities that CAN reach the cluster but should not reach the guest.

That distinction is the one that keeps going wrong: check_cluster_access answers
"can this account see the cluster", and its #248 ACL and #555 pool fallbacks
deliberately let a scoped user through so a per-object gate downstream can decide.
Both directions are asserted here — an over-restriction locks a pool user out of
their own guest, which is just as much a bug. NS
"""
import time

import pytest

import pegaprox.utils.rbac as rbac

CLUSTER = 'cluster_1'
MINE, THEIRS = 100, 200


def _console(client, vmid, vm_type='qemu'):
    return client.get(f'/api/clusters/{CLUSTER}/vms/pve1/{vm_type}/{vmid}/console')


def _term(client, vmid, vm_type='lxc'):
    return client.post(f'/api/clusters/{CLUSTER}/vms/pve1/{vm_type}/{vmid}/termproxy')


def _pool_membership(cluster_id, mapping):
    """Pin the membership map directly — the fake manager has no pools to enumerate, and
    a build that resolves nothing gets cached as suspect and warns."""
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': {f'{vmid}:{vtype}': pool for vmid, (vtype, pool) in mapping.items()},
            'timestamp': time.time(), 'refreshing': False,
        }


@pytest.fixture
def cluster(api):
    mgr = api.make_fake_manager(CLUSTER, get_vnc_ticket={'success': True, 'ticket': 't', 'port': 5900})
    return api.set_manager(CLUSTER, mgr)


@pytest.fixture
def pooled(api, seed, cluster):
    """A pool-scoped operator: console rights, but only over one guest."""
    seed.tenant('t1', clusters=[CLUSTER])
    user = seed.user('pool_op', role='user', tenant_id='t1')
    seed.pool(CLUSTER, 'pool_a', 'pool_op', ['pool.view', 'vm.view', 'vm.console'])
    _pool_membership(CLUSTER, {MINE: ('qemu', 'pool_a')})
    try:
        yield api.as_user(user)
    finally:
        with rbac._pool_cache_lock:
            rbac._pool_membership_cache.pop(CLUSTER, None)


@pytest.fixture
def acled(api, seed, cluster):
    seed.tenant('t2', clusters=[CLUSTER])
    user = seed.user('acl_op', role='user', tenant_id='t2')
    seed.vm_acl(CLUSTER, MINE, ['acl_op'], permissions=['vm.view', 'vm.console'])
    return api.as_user(user)


# ── the guest that is not theirs ─────────────────────────────────────────────

def test_a_pool_user_cannot_open_a_console_for_a_guest_outside_their_pool(pooled):
    """Cluster access is not console access. This is the whole point of the ticket:
    the link is typeable, so the refusal has to come from the server."""
    resp = _console(pooled, THEIRS)

    assert resp.status_code == 403, resp.get_data(as_text=True)[:200]


def test_an_acl_user_cannot_open_a_console_for_a_guest_outside_their_acl(acled):
    resp = _console(acled, THEIRS)

    assert resp.status_code == 403, resp.get_data(as_text=True)[:200]


def test_the_lxc_terminal_leg_refuses_the_same_guest(pooled):
    """The console window carries the VNC/Term toggle into the popup, so termproxy
    is reachable from it too and needs the same answer."""
    resp = _term(pooled, THEIRS)

    assert resp.status_code == 403, resp.get_data(as_text=True)[:200]


def test_a_role_without_vm_console_is_refused_on_a_guest_it_can_otherwise_see(api, seed, cluster):
    """A viewer-ish custom role that grants vm.view but withholds vm.console: the guest
    is on their screen, the console must still not open."""
    seed.tenant('t3', clusters=[CLUSTER])
    user = seed.user('watcher', role='user', tenant_id='t3', denied=['vm.console'])

    resp = _console(api.as_user(user), MINE)

    assert resp.status_code == 403


def test_an_anonymous_caller_gets_nothing(api, cluster):
    assert _console(api.anon(), MINE).status_code in (401, 403)


def test_a_disabled_account_loses_the_console_mid_session(api, seed, db, cluster):
    """A console window outlives the click that opened it; disabling the account has to
    reach it. require_auth re-reads the account, so the next ticket request fails."""
    user = seed.user('leaver', role='admin')
    client = api.as_user(user)
    assert _console(client, MINE).status_code == 200

    db.save_user('leaver', {**user, 'enabled': False})

    assert _console(client, MINE).status_code in (401, 403)


# ── and the guest that IS theirs (the over-restriction direction) ────────────

def test_a_pool_user_still_opens_a_console_for_their_own_guest(pooled):
    """The failure mode a tightened gate produces: the pool operator is locked out of the
    guest the pool exists to give them."""
    resp = _console(pooled, MINE)

    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]


def test_an_acl_user_still_opens_a_console_for_their_own_guest(acled):
    resp = _console(acled, MINE)

    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]


def test_an_admin_is_unaffected(api, seed, cluster):
    client = api.as_user(seed.user('root_admin', role='admin'))

    assert _console(client, THEIRS).status_code == 200


# ── the read the console window itself depends on ────────────────────────────

def test_the_cluster_list_the_window_resolves_its_host_from_is_scoped(api, seed, cluster):
    """StandaloneConsole refuses anything /api/clusters does not return, so that list is
    load-bearing for the window even though it predates it."""
    seed.tenant('t4', clusters=[])
    other = api.as_user(seed.user('outsider', role='user', tenant_id='t4'))

    ids = [c['id'] for c in (other.get('/api/clusters').get_json() or [])]

    assert CLUSTER not in ids


def test_a_portal_account_is_still_bound_by_its_scope(api, seed, cluster):
    """A console link is the one piece of PegaProx UI a portal user can type by hand. Since
    Oct 2026 the server holds portal_only (test_portal_only_is_enforced_on_the_server.py):
    the main API's console is not the portal's, so even the account's own pooled guest is
    refused here, and the portal opens it through its own route instead."""
    seed.tenant('t5', clusters=[CLUSTER])
    user = seed.user('portal_user', role='user', tenant_id='t5', portal_only=True)
    seed.pool(CLUSTER, 'pool_p', 'portal_user', ['pool.view', 'vm.view', 'vm.console'])
    _pool_membership(CLUSTER, {MINE: ('qemu', 'pool_p')})
    try:
        client = api.as_user(user)

        assert _console(client, THEIRS).status_code == 403
        r = _console(client, MINE)
        assert r.status_code == 403 and r.get_json()['code'] == 'PORTAL_ONLY', r.data
    finally:
        with rbac._pool_cache_lock:
            rbac._pool_membership_cache.pop(CLUSTER, None)
