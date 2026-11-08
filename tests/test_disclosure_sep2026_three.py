"""Three findings from a private report against 1.1.0, re-verified after they were
mistakenly announced as fixed.

The first two were reported, believed fixed, and were not. The reporter checked the
released build and said so. Worth keeping the exact scenarios, because both slipped for
the same reason: a shared helper was written to cover the case, other call sites moved
onto it, and these did not. MK
"""
import pytest

CLUSTER = 'cluster_1'
VMS = [
    {'vmid': 100, 'name': 'granted', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 200, 'name': 'other-a', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 300, 'name': 'other-b', 'node': 'pve2', 'type': 'lxc',  'status': 'stopped'},
]


def _mgr(api):
    m = api.make_fake_manager(CLUSTER, get_vm_resources=list(VMS))
    m.is_connected = True
    return api.set_manager(CLUSTER, m)


def test_an_acl_scoped_user_sees_only_their_vm_on_a_tenant_owned_cluster(api, seed):
    """The reported case. The tenant OWNS the cluster, so the caller is not a #248/#555
    fallback; they are confined by a VM-ACL instead of a pool. The old predicate here asked
    `(not owner) or has_pool_access`, so neither leg was true and they fell into the listing
    whose `elif has_general_view` arm returns every VM without an ACL entry of its own."""
    seed.tenant('acme', clusters=[CLUSTER])
    user = seed.user('scoped', role='user', tenant_id='acme')
    seed.vm_acl(CLUSTER, 100, ['scoped'], permissions=['vm.view'])
    _mgr(api)

    r = api.as_user(user).get(f'/api/clusters/{CLUSTER}/resources')

    assert r.status_code == 200
    assert sorted(v['vmid'] for v in r.get_json()) == [100]


def test_a_plain_operator_on_their_own_cluster_still_sees_all_of_it(api, seed):
    """The other direction — the tenant's ordinary operator has no pool and no ACL, and must
    keep the whole-cluster view. Tightening the gate without this is how the fix would break
    every normal multi-tenant setup."""
    seed.tenant('acme', clusters=[CLUSTER])
    user = seed.user('operator', role='user', tenant_id='acme')
    _mgr(api)

    r = api.as_user(user).get(f'/api/clusters/{CLUSTER}/resources')

    assert sorted(v['vmid'] for v in r.get_json()) == [100, 200, 300]


def test_the_predicate_is_the_shared_one_not_a_local_copy():
    """Why it slipped: helpers.caller_is_scoped exists precisely because the open-coded form
    misses the ACL-scoped tenant-owner, and its docstring says so. This endpoint kept its own
    copy anyway."""
    src = open('pegaprox/api/clusters.py', encoding='utf-8').read()
    fn = src[src.index('def get_cluster_resources'):]
    fn = fn[:fn.index('\n@bp.route')]
    # strip comments — the fix explains the old predicate by name, and matching that would
    # make this test pass or fail on prose rather than on code (it already did once)
    code = '\n'.join(l for l in fn.split('\n') if not l.lstrip().startswith('#'))

    assert 'caller_is_scoped' in code
    assert 'user_has_any_pool_access' not in code, 'the local predicate is back'


def test_the_portal_logout_tells_the_server(api):
    """Clicking Logout cleared the browser and left the session valid — a reload answered
    /api/auth/check with authenticated:true and the cookie kept working until it timed out."""
    src = open('plugins/client_portal/portal.html', encoding='utf-8').read()
    fn = src[src.index('function logout(){'):]
    fn = fn[:fn.index('\n}')]

    assert 'auth/logout' in fn
    assert "method:'POST'" in fn
    assert 'sessionStorage.removeItem' in fn, 'local teardown was lost'


def test_the_logout_endpoint_actually_invalidates(api, seed):
    """The other half: the call is only worth making if the endpoint revokes the session."""
    user = seed.user('portal_user', role='user')
    client = api.as_user(user)
    assert client.get('/api/auth/check').get_json().get('authenticated') is True

    client.post('/api/auth/logout')

    assert client.get('/api/auth/check').get_json().get('authenticated') is not True


@pytest.mark.parametrize('verb', ['PUT', 'DELETE'])
def test_the_pool_routes_are_registered_once(api, verb):
    """Both were registered in users.py and static_files.py. Whichever blueprint loaded first
    silently won, so the pair could drift apart in permissions with no way to tell which was
    in force from reading either file."""
    rule = '/api/clusters/<cluster_id>/pools/<pool_id>'
    hits = [r for r in api.app.url_map.iter_rules() if str(r) == rule and verb in r.methods]

    assert len(hits) == 1, f'{verb} registered {len(hits)}x: {[h.endpoint for h in hits]}'


def test_the_tenant_cluster_hint_no_longer_says_empty_means_all():
    """A side note in the same report: with an empty list a non-default tenant sees NO
    clusters, not all of them."""
    src = open('web/src/settings_modal.js', encoding='utf-8').read()

    assert 'empty = all' not in src
