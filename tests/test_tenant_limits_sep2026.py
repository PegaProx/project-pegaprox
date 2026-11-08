"""Three additions to the tenant model: a disk ceiling, a VMID slice, and the tenant list
the switcher reads.

Disk is the fourth quota dimension and behaves exactly like cores/memory/vms — 0 is unlimited,
the enforce mode decides block-vs-warn, and any error inside the check still fails open, because
a quota bug must never stop a legitimate create.

The VMID range deliberately does NOT fail open in the same way. It exists to stop two tenants
landing on the same id on a shared cluster, and a collision that is allowed through "just this
once" is one nobody notices until a restore picks the wrong guest.

/api/me/tenants is the one to be careful with: it is presentational. It says what a switcher may
offer, never what a caller may do. The tests below pin that distinction, because the last two
authz bugs in this codebase both came from a scoping answer being trusted one layer further than
it was meant to go. NS
"""
import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.rbac import check_tenant_quota, check_tenant_vmid, tenant_vmid_range


CLUSTER = 'cluster_1'


def _tenant(db, tid='acme', **cols):
    row = {'id': tid, 'name': tid.title(), 'clusters': [CLUSTER]}
    row.update(cols)
    db.save_tenant(tid, row)
    rbac.invalidate_tenants_cache()
    return tid


# ── disk quota ───────────────────────────────────────────────────────────────

def test_disk_quota_blocks_a_create_that_would_exceed_it(db, api):
    """The dimension an MSP runs out of first, and the only one of the four a tenant could
    previously grow without limit."""
    tid = _tenant(db, quota_max_disk_gb=100)
    m = api.make_fake_manager(CLUSTER)
    m.get_vm_resources = lambda: [{'vmid': 100, 'maxdisk': 90 * 1024 ** 3}]
    api.set_manager(CLUSTER, m)

    r = check_tenant_quota(tid, add_disk_gb=20, add_vms=1)

    assert r['ok'] is False
    assert 'disk' in r['violations']


def test_disk_quota_allows_a_create_that_fits(db, api):
    tid = _tenant(db, quota_max_disk_gb=100)
    m = api.make_fake_manager(CLUSTER)
    m.get_vm_resources = lambda: [{'vmid': 100, 'maxdisk': 40 * 1024 ** 3}]
    api.set_manager(CLUSTER, m)

    assert check_tenant_quota(tid, add_disk_gb=20, add_vms=1)['ok'] is True


def test_zero_means_unlimited_like_the_other_three(db, api):
    tid = _tenant(db, quota_max_disk_gb=0)
    m = api.make_fake_manager(CLUSTER)
    m.get_vm_resources = lambda: [{'vmid': 100, 'maxdisk': 9000 * 1024 ** 3}]
    api.set_manager(CLUSTER, m)

    assert check_tenant_quota(tid, add_disk_gb=5000, add_vms=1)['ok'] is True


def test_usage_and_quota_report_disk_for_the_display(db, api):
    """The portal renders usage before the form is submitted; it needs the fourth number."""
    tid = _tenant(db, quota_max_disk_gb=500)
    m = api.make_fake_manager(CLUSTER)
    m.get_vm_resources = lambda: [{'vmid': 100, 'maxdisk': 32 * 1024 ** 3}]
    api.set_manager(CLUSTER, m)

    r = check_tenant_quota(tid, add_vms=0, force=True)

    assert r['usage']['disk_gb'] == 32.0
    assert r['quota']['disk_gb'] == 500


def test_a_broken_cluster_walk_cannot_block_on_phantom_usage(db, api):
    """The real contract, which I got wrong at first and the run corrected: the per-manager call
    has its own except that sets vms=[], so a cluster that blows up mid-walk contributes ZERO
    usage rather than tipping someone over their limit. The requested amount is still measured —
    asking for 9999 GB against a 1 GB ceiling is refused on the request alone. Pre-existing for
    all four dimensions; pinned here because disk now rides the same path."""
    tid = _tenant(db, quota_max_disk_gb=1)

    def _boom():
        raise RuntimeError('cluster went away mid-walk')
    m = api.make_fake_manager(CLUSTER)
    m.get_vm_resources = _boom
    api.set_manager(CLUSTER, m)

    assert check_tenant_quota(tid, add_disk_gb=9999, add_vms=1)['ok'] is False   # request itself
    assert check_tenant_quota(tid, add_disk_gb=0, add_vms=1)['usage']['disk_gb'] == 0.0


def test_a_tenant_lookup_failure_still_fails_open(db, api, monkeypatch):
    """The outer guard: anything that breaks before the walk must allow the create through."""
    tid = _tenant(db, quota_max_disk_gb=1)
    monkeypatch.setattr(rbac, 'load_tenants', lambda: (_ for _ in ()).throw(RuntimeError('db gone')))

    assert check_tenant_quota(tid, add_disk_gb=9999, add_vms=1)['ok'] is True


# ── VMID range ───────────────────────────────────────────────────────────────

def test_a_vmid_inside_the_range_is_accepted(db):
    tid = _tenant(db, vmid_range_start=2000, vmid_range_end=2999)

    assert check_tenant_vmid(tid, 2500) == (True, '')


@pytest.mark.parametrize('vmid', [1999, 3000, 100])
def test_a_vmid_outside_the_range_is_refused(db, vmid):
    tid = _tenant(db, vmid_range_start=2000, vmid_range_end=2999)

    ok, msg = check_tenant_vmid(tid, vmid)

    assert ok is False
    assert '2000-2999' in msg


def test_no_range_configured_accepts_everything(db):
    """Every install that has not asked for a range must be untouched."""
    tid = _tenant(db)

    assert check_tenant_vmid(tid, 12345) == (True, '')


def test_an_inverted_range_degrades_to_no_range(db):
    """Belt and braces behind the API validation — malformed must never enforce half a rule."""
    tid = _tenant(db, vmid_range_start=3000, vmid_range_end=2000)

    assert tenant_vmid_range(tid) == (0, 0)
    assert check_tenant_vmid(tid, 100) == (True, '')


def test_the_boundaries_are_inclusive(db):
    tid = _tenant(db, vmid_range_start=2000, vmid_range_end=2999)

    assert check_tenant_vmid(tid, 2000)[0] is True
    assert check_tenant_vmid(tid, 2999)[0] is True


def test_an_unparseable_vmid_is_left_to_the_allocator(db):
    """No id supplied means PVE (or our nextid route) picks one; there is nothing to judge here.
    The route is what keeps that pick inside the range — see the nextid tests."""
    tid = _tenant(db, vmid_range_start=2000, vmid_range_end=2999)

    assert check_tenant_vmid(tid, None)[0] is True
    assert check_tenant_vmid(tid, 'abc')[0] is True


# ── the nextid route has to offer an id the range will accept ────────────────

def test_nextid_offers_the_first_free_id_inside_the_range(api, seed, db):
    """Otherwise the range is only ever a rejection: the dialog pre-fills from this route, so a
    user would be handed an id their own tenant then refuses."""
    _tenant(db, tid='acme', vmid_range_start=2000, vmid_range_end=2999)
    user = seed.user('op', role='user', tenant_id='acme')
    m = api.make_fake_manager(CLUSTER)
    m.get_next_vmid = lambda: {'success': True, 'vmid': 101}
    m.get_vm_resources = lambda: [{'vmid': 2000}, {'vmid': 2001}]
    api.set_manager(CLUSTER, m)

    r = api.as_user(user).get(f'/api/clusters/{CLUSTER}/nextid')

    assert r.status_code == 200
    assert r.get_json()['vmid'] == 2002


def test_nextid_is_unchanged_for_a_tenant_without_a_range(api, seed, db):
    _tenant(db, tid='acme')
    user = seed.user('op', role='user', tenant_id='acme')
    m = api.make_fake_manager(CLUSTER)
    m.get_next_vmid = lambda: {'success': True, 'vmid': 101}
    api.set_manager(CLUSTER, m)

    r = api.as_user(user).get(f'/api/clusters/{CLUSTER}/nextid')

    assert r.get_json()['vmid'] == 101


def test_a_full_range_says_so_instead_of_pretending(api, seed, db):
    """Silently handing back an out-of-range id would produce a create that then fails with a
    confusing 403. Say the range is full and let the caller see it."""
    _tenant(db, tid='acme', vmid_range_start=2000, vmid_range_end=2001)
    user = seed.user('op', role='user', tenant_id='acme')
    m = api.make_fake_manager(CLUSTER)
    m.get_next_vmid = lambda: {'success': True, 'vmid': 101}
    m.get_vm_resources = lambda: [{'vmid': 2000}, {'vmid': 2001}]
    api.set_manager(CLUSTER, m)

    body = api.as_user(user).get(f'/api/clusters/{CLUSTER}/nextid').get_json()

    assert body.get('range_exhausted') is True
    assert body['range'] == [2000, 2001]


# ── the tenant list behind the switcher ──────────────────────────────────────

def test_the_switcher_list_includes_a_delegated_tenant(api, seed, db):
    """/api/tenants only ever knew the home tenant; someone delegated into a second one had no
    way to tell the UI about it."""
    _tenant(db, tid='home')
    _tenant(db, tid='other')
    user = seed.user('dele', role='user', tenant_id='home',
                     tenant_permissions={'other': {'role': 'viewer', 'extra': [], 'denied': []}})

    body = api.as_user(user).get('/api/me/tenants').get_json()

    assert body['home'] == 'home'
    assert sorted(t['id'] for t in body['tenants']) == ['home', 'other']


def test_a_stale_permission_entry_does_not_invent_a_tenant(api, seed, db):
    """tenant_permissions outlives a deleted tenant; the list must not resurrect it."""
    _tenant(db, tid='home')
    user = seed.user('dele', role='user', tenant_id='home',
                     tenant_permissions={'deleted_long_ago': {'role': 'viewer'}})

    body = api.as_user(user).get('/api/me/tenants').get_json()

    assert [t['id'] for t in body['tenants']] == ['home']


def test_an_admin_sees_every_tenant(api, seed, db):
    _tenant(db, tid='home')
    _tenant(db, tid='other')
    admin = seed.user('root_admin', role='admin')

    body = api.as_user(admin).get('/api/me/tenants').get_json()

    assert {'home', 'other'} <= {t['id'] for t in body['tenants']}


def test_the_list_is_not_an_authorisation_answer(api, seed, db):
    """The point of the whole endpoint. A plain user must not appear to hold anything in a tenant
    they were never delegated into, and nothing downstream reads this to decide access."""
    _tenant(db, tid='home')
    _tenant(db, tid='foreign')
    user = seed.user('plain', role='user', tenant_id='home')

    body = api.as_user(user).get('/api/me/tenants').get_json()

    assert [t['id'] for t in body['tenants']] == ['home']
    src = open('pegaprox/api/users.py').read()
    fn = src[src.index('def get_my_tenants('):src.index("@bp.route('/api/tenants', methods=['POST'])")]
    assert 'request.args' not in fn and 'request.json' not in fn, \
        'the switcher list must derive everything from the session, never from the client'


# ── who may move the range ───────────────────────────────────────────────────

def test_only_a_global_admin_may_change_the_range(api, seed, db):
    """Found in my own audit of this change, not by a tool. The range separates customers, so a
    tenant admin who could widen their own slice to 100-999999 would erase the very thing it is
    for. Sits with `clusters`, not with the quotas."""
    _tenant(db, tid='acme', vmid_range_start=2000, vmid_range_end=2999)
    ta = seed.user('t_admin', role='user', tenant_id='acme', permissions=['admin.tenants'])

    r = api.as_user(ta).put('/api/tenants/acme', json={'vmid_range_start': 100,
                                                       'vmid_range_end': 999999})

    assert r.status_code == 403
    assert tenant_vmid_range('acme') == (2000, 2999), 'the stored range moved anyway'


def test_a_tenant_admin_may_still_edit_the_rest(api, seed, db):
    """The guard must not turn into a blanket refusal — that is how the last over-restriction
    got shipped. Name and quota stay editable for a tenant-scoped admin."""
    _tenant(db, tid='acme', vmid_range_start=2000, vmid_range_end=2999)
    ta = seed.user('t_admin', role='user', tenant_id='acme', permissions=['admin.tenants'])

    r = api.as_user(ta).put('/api/tenants/acme', json={'name': 'Acme GmbH',
                                                       'quota_max_disk_gb': 500,
                                                       'vmid_range_start': 2000,
                                                       'vmid_range_end': 2999})

    assert r.status_code == 200, r.get_data(as_text=True)


def test_a_global_admin_can_move_it(api, seed, db):
    _tenant(db, tid='acme', vmid_range_start=2000, vmid_range_end=2999)
    admin = seed.user('root_admin', role='admin')

    r = api.as_user(admin).put('/api/tenants/acme', json={'vmid_range_start': 3000,
                                                          'vmid_range_end': 3999})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert tenant_vmid_range('acme') == (3000, 3999)


@pytest.mark.parametrize('start,end,why', [
    (50, 999, 'below the 100 PVE reserves'),
    (3000, 2000, 'inverted'),
])
def test_a_malformed_range_is_refused_not_swallowed(api, seed, db, start, end, why):
    """tenant_vmid_range treats malformed as 'no range', so storing it would show a saved range
    in the UI that enforces nothing."""
    _tenant(db, tid='acme')
    admin = seed.user('root_admin', role='admin')

    r = api.as_user(admin).put('/api/tenants/acme', json={'vmid_range_start': start,
                                                          'vmid_range_end': end})

    assert r.status_code == 400, why


# ── the limit fields must not be a crash path ────────────────────────────────

@pytest.mark.parametrize('field', ['vmid_range_start', 'vmid_range_end',
                                   'quota_max_disk_gb', 'quota_max_vms'])
def test_a_non_numeric_limit_is_refused_not_a_500(api, seed, db, field):
    """Found by the scan on this change and confirmed against the running instance: both the
    create and the update route answered 500 for {"vmid_range_start": "abc"}. The pre-existing
    quota fields had the same shape, so they are covered by the same validator now."""
    _tenant(db, tid='acme')
    admin = seed.user('root_admin', role='admin')

    r = api.as_user(admin).put('/api/tenants/acme', json={field: 'abc'})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert field in r.get_json()['error']


def test_a_negative_limit_is_refused(api, seed, db):
    _tenant(db, tid='acme')
    admin = seed.user('root_admin', role='admin')

    r = api.as_user(admin).put('/api/tenants/acme', json={'quota_max_disk_gb': -5})

    assert r.status_code == 400


def test_a_garbage_quota_does_not_silently_become_unlimited(api, seed, db):
    """The update path used to swallow an unparseable value to 0, which for a LIMIT means a typo
    quietly removed the ceiling. Refusing is the safe direction."""
    _tenant(db, tid='acme', quota_max_disk_gb=500)
    admin = seed.user('root_admin', role='admin')

    api.as_user(admin).put('/api/tenants/acme', json={'quota_max_disk_gb': 'oops'})
    rbac.invalidate_tenants_cache()

    assert (rbac.load_tenants()['acme']['quota_max_disk_gb']) == 500, 'the ceiling was dropped'


def test_an_empty_string_still_means_zero(api, seed, db):
    """The form posts '' for a cleared field; that has to keep meaning 'no limit', not 400."""
    _tenant(db, tid='acme', quota_max_disk_gb=500)
    admin = seed.user('root_admin', role='admin')

    r = api.as_user(admin).put('/api/tenants/acme', json={'quota_max_disk_gb': ''})

    assert r.status_code == 200
    rbac.invalidate_tenants_cache()
    assert rbac.load_tenants()['acme']['quota_max_disk_gb'] == 0
