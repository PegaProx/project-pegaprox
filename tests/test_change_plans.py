"""Change plans: four-eyes approval, who may approve what, the state machine, the window,
and the link from config drift to an approved plan.

NS Oct 2026 - basic stage of the Change Guardian. Nothing runs and nothing is blocked; a plan
is a request that a second administrator approves, and drift reads the approved ones.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.api import drift
from pegaprox.core import changes, ha
from pegaprox.models.permissions import PERMISSIONS, ROLE_PERMISSIONS
from pegaprox.utils.auth import create_api_token

CL = 'cluster_1'
OTHER = 'cluster_2'
TENANT_PERMS = ['changes.view', 'changes.request', 'changes.approve', 'vm.view']


def _iso(**delta):
    return changes.iso_utc(datetime.now(timezone.utc) + timedelta(**delta))


@pytest.fixture
def estate(api, seed, db):
    for cid in (CL, OTHER):
        db.conn.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                           VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (cid, cid))
        m = api.make_fake_manager(cid)
        m.is_connected = True
        api.set_manager(cid, m)
    db.conn.commit()
    # acme owns cluster_1 and the VMIDs 100-199, globex owns cluster_2
    db.save_tenant('acme', {'name': 'acme', 'clusters': [CL], 'vmid_range_start': 100,
                            'vmid_range_end': 199})
    db.save_tenant('globex', {'name': 'globex', 'clusters': [OTHER]})
    from pegaprox.utils import rbac
    rbac.invalidate_tenants_cache()
    seed.admin = lambda name: api.as_user(seed.user(name, role='admin'))
    seed.tenant_holder = lambda name, tenant='acme', perms=TENANT_PERMS: api.as_user(
        seed.user(name, role='viewer', tenant_id=tenant, permissions=list(perms)))
    return seed


def _plan_body(kind='guests', targets=(150,), **kw):
    body = {'cluster_id': CL, 'title': 'Patch the web tier', 'description': 'kernel update',
            'scope': {'kind': kind, 'targets': list(targets)},
            'window_start': _iso(minutes=30), 'window_end': _iso(hours=3)}
    body.update(kw)
    return body


def _make(client, status='draft', **kw):
    """A plan the client requested, taken to `status` through the routes."""
    r = client.post('/api/changes', json=_plan_body(**kw))
    assert r.status_code == 201, r.get_data(as_text=True)
    pid = r.get_json()['id']
    if status != 'draft':
        s = client.post(f'/api/changes/{pid}/submit')
        assert s.status_code == 200, s.get_data(as_text=True)
    return pid


def _status(db, pid):
    return db.query_one('SELECT status FROM change_plans WHERE id = ?', (pid,))['status']


def _insert(db, pid='p1', status='approved', cluster=CL, kind='cluster', targets=(), start=None, end=None,
            requested_by='alice', title='Planned'):
    now = _iso()
    db.conn.execute(
        'INSERT INTO change_plans (id, cluster_id, title, scope, window_start, window_end, status, '
        'requested_by, approved_by, approved_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        (pid, cluster, title, json.dumps({'kind': kind, 'targets': list(targets)}),
         start or _iso(hours=-1), end or _iso(hours=1), status, requested_by, 'bob', now, now, now))
    db.conn.commit()


# -- the permissions ------------------------------------------------------------------------

def test_the_permissions_exist_and_the_builtin_roles_do_not_hold_them():
    for p in ('changes.view', 'changes.request', 'changes.approve'):
        assert p in PERMISSIONS
        assert p in ROLE_PERMISSIONS['admin']
        assert p not in ROLE_PERMISSIONS['user'] and p not in ROLE_PERMISSIONS['viewer']


def test_a_plain_user_cannot_even_list(estate, api):
    u = api.as_user(estate.user('plain', role='user'))
    assert u.get('/api/changes').status_code == 403
    assert u.post('/api/changes', json=_plan_body()).status_code == 403


def test_the_permissions_are_listed_for_the_role_editor(estate, api):
    r = estate.admin('root').get('/api/permissions')
    assert r.status_code == 200
    assert {'changes.view', 'changes.request', 'changes.approve'} <= {p['permission'] for p in r.get_json()}


# -- four eyes ------------------------------------------------------------------------------

def test_the_requester_does_not_approve_or_reject_their_own_plan(estate, db):
    alice = estate.admin('alice')
    pid = _make(alice, 'submitted', kind='cluster', targets=())
    a = alice.post(f'/api/changes/{pid}/approve')
    assert a.status_code == 403 and a.get_json()['code'] == 'OWN_PLAN', a.get_data(as_text=True)
    assert alice.post(f'/api/changes/{pid}/reject', json={'reason': 'no'}).status_code == 403
    assert _status(db, pid) == 'submitted'


def test_a_second_session_of_the_same_account_is_the_same_person(estate, api, db):
    alice = estate.admin('alice')
    pid = _make(alice, 'submitted')
    again = api.as_user(estate.user('alice', role='admin'))
    assert again.post(f'/api/changes/{pid}/approve').status_code == 403
    assert _status(db, pid) == 'submitted'


def test_the_api_token_of_the_requester_does_not_approve_either(estate, api, db):
    alice = estate.admin('alice')
    pid = _make(alice, 'submitted')
    tok = create_api_token('alice', 'ci', role='admin', expires_days=1)['token']
    bare = api.anon()
    r = bare.post(f'/api/changes/{pid}/approve', headers={'Authorization': f'Bearer {tok}'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'OWN_PLAN'
    assert _status(db, pid) == 'submitted'


def test_a_plan_requested_with_a_token_belongs_to_its_owner(estate, api, db):
    estate.user('alice', role='admin')
    tok = create_api_token('alice', 'ci', role='admin', expires_days=1)['token']
    r = api.anon().post('/api/changes', json=_plan_body(), headers={'Authorization': f'Bearer {tok}'})
    assert r.status_code == 201, r.get_data(as_text=True)
    assert r.get_json()['requested_by'] == 'alice'


def test_another_admin_approves_and_it_is_audited(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    pid = _make(alice, 'submitted')
    r = bob.post(f'/api/changes/{pid}/approve')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['status'] == 'approved' and body['approved_by'] == 'bob' and body['approved_at']
    actions = [(e['user'], e['action']) for e in db.query('SELECT user, action FROM audit_log')]
    assert ('alice', 'change.create') in actions
    assert ('alice', 'change.submit') in actions
    assert ('bob', 'change.approve') in actions


def test_a_rejection_needs_a_reason_and_is_kept(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    pid = _make(alice, 'submitted')
    assert bob.post(f'/api/changes/{pid}/reject', json={}).status_code == 400
    assert bob.post(f'/api/changes/{pid}/reject', json={'reason': '   '}).status_code == 400
    assert _status(db, pid) == 'submitted'
    r = bob.post(f'/api/changes/{pid}/reject', json={'reason': 'window collides with the backup'})
    assert r.status_code == 200
    body = r.get_json()
    assert (body['status'], body['rejected_by'], body['reject_reason']) == \
        ('rejected', 'bob', 'window collides with the backup')
    assert ('bob', 'change.reject') in [(e['user'], e['action']) for e in db.query('SELECT user, action FROM audit_log')]


def test_the_page_is_told_why_approve_is_off(estate):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    pid = _make(alice, 'submitted')
    mine = alice.get(f'/api/changes/{pid}').get_json()
    assert mine['can']['approve'] is False and mine['approve_blocked'] == 'own_plan'
    assert mine['approve_blocked_reason']
    theirs = bob.get(f'/api/changes/{pid}').get_json()
    assert theirs['can']['approve'] is True and theirs['approve_blocked'] == ''


# -- who approves what ----------------------------------------------------------------------

def test_a_tenant_admin_approves_a_plan_for_guests_of_their_tenant(estate, db):
    pid = _make(estate.admin('alice'), 'submitted', kind='guests', targets=(120, 130))
    ta = estate.tenant_holder('tadmin')
    r = ta.post(f'/api/changes/{pid}/approve')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _status(db, pid) == 'approved'


@pytest.mark.parametrize('kind', [k for k in changes.KINDS if k != 'guests'])
def test_a_tenant_admin_never_approves_a_cluster_wide_kind(estate, db, kind):
    targets = () if kind == 'cluster' else ('thing',)
    pid = _make(estate.admin('alice'), 'submitted', kind=kind, targets=targets)
    ta = estate.tenant_holder('tadmin')
    r = ta.post(f'/api/changes/{pid}/approve')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'OUT_OF_SCOPE'
    assert ta.post(f'/api/changes/{pid}/reject', json={'reason': 'x'}).status_code == 403
    assert _status(db, pid) == 'submitted'
    seen = ta.get(f'/api/changes/{pid}').get_json()
    assert seen['can']['approve'] is False and seen['approve_blocked'] == 'out_of_scope'


def test_a_tenant_admin_does_not_approve_a_guest_outside_their_tenant(estate, db):
    # 250 lies outside the VMID slice of acme, 150 inside; one foreign guest sinks the plan
    pid = _make(estate.admin('alice'), 'submitted', kind='guests', targets=(150, 250))
    ta = estate.tenant_holder('tadmin')
    r = ta.post(f'/api/changes/{pid}/approve')
    assert r.status_code == 403 and r.get_json()['code'] == 'OUT_OF_SCOPE'
    assert _status(db, pid) == 'submitted'


def test_a_tenant_admin_does_not_approve_on_a_cluster_of_another_tenant(estate, db):
    pid = _make(estate.admin('alice'), 'submitted', kind='guests', targets=(150,), cluster_id=OTHER)
    ta = estate.tenant_holder('tadmin')
    assert ta.post(f'/api/changes/{pid}/approve').status_code in (403, 404)
    assert _status(db, pid) == 'submitted'


def test_a_holder_without_the_permission_does_not_approve(estate, db):
    pid = _make(estate.admin('alice'), 'submitted', kind='guests', targets=(150,))
    asker = estate.tenant_holder('asker', perms=['changes.view', 'changes.request', 'vm.view'])
    assert asker.post(f'/api/changes/{pid}/approve').status_code == 403
    assert _status(db, pid) == 'submitted'


# -- reach ----------------------------------------------------------------------------------

def test_a_requester_cannot_create_a_plan_for_a_cluster_outside_their_reach(estate, db):
    ta = estate.tenant_holder('tadmin')
    r = ta.post('/api/changes', json=_plan_body(cluster_id=OTHER))
    assert r.status_code == 404
    assert db.query_one('SELECT COUNT(*) AS n FROM change_plans')['n'] == 0


def test_a_requester_cannot_plan_a_guest_they_do_not_reach(estate, api):
    # a pool/ACL-scoped user: only VM 120 of cluster_1
    client = _scoped(estate, api)
    assert client.post('/api/changes', json=_plan_body(targets=(120,))).status_code == 201
    r = client.post('/api/changes', json=_plan_body(targets=(120, 121)))
    assert r.status_code == 403, r.get_data(as_text=True)


def _scoped(estate, api):
    """A requester of tenant acme who holds the VM ACL of guest 120 only."""
    user = estate.user('scoped', role='viewer', tenant_id='acme', permissions=TENANT_PERMS)
    estate.vm_acl(CL, 120, ['scoped'])
    return api.as_user(user)


def test_a_confined_requester_cannot_ask_for_a_cluster_wide_change(estate, api, db):
    client = _scoped(estate, api)
    for kind, targets in (('storage', ['local']), ('cluster', [])):
        r = client.post('/api/changes', json=_plan_body(kind=kind, targets=targets))
        assert r.status_code == 403, (kind, r.get_data(as_text=True))
    assert db.query_one('SELECT COUNT(*) AS n FROM change_plans')['n'] == 0


def test_the_list_shows_only_plans_of_reachable_clusters(estate):
    admin = estate.admin('alice')
    mine = _make(admin, kind='guests', targets=(150,))
    theirs = _make(admin, kind='guests', targets=(150,), cluster_id=OTHER)
    ta = estate.tenant_holder('tadmin')
    ids = {p['id'] for p in ta.get('/api/changes').get_json()['changes']}
    assert ids == {mine}
    assert ta.get(f'/api/changes/{theirs}').status_code == 404
    assert ta.get(f'/api/changes?cluster={OTHER}').status_code == 403
    both = {p['id'] for p in estate.admin('bob').get('/api/changes').get_json()['changes']}
    assert both == {mine, theirs}


def test_a_confined_reader_sees_the_plans_for_their_guests_and_their_own(estate, api):
    admin = estate.admin('alice')
    client = _scoped(estate, api)
    theirs = _make(admin, kind='guests', targets=(120,))
    other_guest = _make(admin, kind='guests', targets=(121,))
    wide = _make(admin, kind='storage', targets=('local',))
    own = _make(client, kind='guests', targets=(120,))
    ids = {p['id'] for p in client.get('/api/changes').get_json()['changes']}
    assert ids == {theirs, own}
    assert client.get(f'/api/changes/{other_guest}').status_code == 404
    assert client.get(f'/api/changes/{wide}').status_code == 404


def test_the_list_filters_by_cluster_and_status(estate):
    admin = estate.admin('alice')
    a = _make(admin, 'submitted')
    b = _make(admin, 'draft')
    c = _make(admin, cluster_id=OTHER)
    got = lambda q: {p['id'] for p in admin.get('/api/changes' + q).get_json()['changes']}  # noqa: E731
    assert got('') == {a, b, c}
    assert got(f'?cluster={CL}') == {a, b}
    assert got('?status=submitted') == {a}
    assert got(f'?cluster={OTHER}&status=draft') == {c}
    assert admin.get('/api/changes?status=nonsense').status_code == 400


# -- the state machine ----------------------------------------------------------------------

def test_a_plan_walks_draft_submitted_approved_done(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    pid = _make(alice)
    assert _status(db, pid) == 'draft'
    assert alice.post(f'/api/changes/{pid}/submit').status_code == 200
    assert bob.post(f'/api/changes/{pid}/approve').status_code == 200
    assert alice.post(f'/api/changes/{pid}/done').status_code == 200
    assert _status(db, pid) == 'done'


def test_invalid_transitions_are_409_and_change_nothing(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    draft = _make(alice)
    submitted = _make(alice, 'submitted')
    approved = _make(alice, 'submitted')
    assert bob.post(f'/api/changes/{approved}/approve').status_code == 200
    rejected = _make(alice, 'submitted')
    assert bob.post(f'/api/changes/{rejected}/reject', json={'reason': 'no'}).status_code == 200
    cancelled = _make(alice)
    assert alice.post(f'/api/changes/{cancelled}/cancel').status_code == 200
    done = _make(alice, 'submitted')
    assert bob.post(f'/api/changes/{done}/approve').status_code == 200
    assert alice.post(f'/api/changes/{done}/done').status_code == 200

    bad = [
        (bob, draft, 'approve'), (bob, draft, 'reject'), (alice, draft, 'done'),
        (alice, submitted, 'submit'), (alice, submitted, 'done'),
        (bob, approved, 'approve'), (bob, approved, 'reject'), (alice, approved, 'submit'),
        (bob, rejected, 'approve'), (alice, rejected, 'submit'), (alice, rejected, 'cancel'),
        (alice, cancelled, 'submit'), (bob, cancelled, 'approve'), (alice, cancelled, 'cancel'),
        (alice, done, 'cancel'), (alice, done, 'done'), (bob, done, 'approve'),
    ]
    for who, pid, action in bad:
        body = {'reason': 'x'} if action == 'reject' else None
        r = who.post(f'/api/changes/{pid}/{action}', json=body) if body else who.post(f'/api/changes/{pid}/{action}')
        assert r.status_code == 409, (pid, action, r.status_code, r.get_data(as_text=True))
    assert [_status(db, p) for p in (draft, submitted, approved, rejected, cancelled, done)] == \
        ['draft', 'submitted', 'approved', 'rejected', 'cancelled', 'done']


def test_only_the_requester_edits_and_only_a_draft(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    pid = _make(alice)
    assert bob.put(f'/api/changes/{pid}', json={'title': 'mine now'}).status_code == 403
    r = alice.put(f'/api/changes/{pid}', json={'title': 'Renamed', 'scope': {'kind': 'guests', 'targets': [150, 151]}})
    assert r.status_code == 200 and r.get_json()['title'] == 'Renamed'
    assert r.get_json()['scope']['targets'] == [150, 151]
    assert alice.put(f'/api/changes/{pid}', json={}).status_code == 400
    assert alice.post(f'/api/changes/{pid}/submit').status_code == 200
    assert alice.put(f'/api/changes/{pid}', json={'title': 'again'}).status_code == 409
    assert bob.post(f'/api/changes/{pid}/approve').status_code == 200
    assert alice.put(f'/api/changes/{pid}', json={'title': 'after approval'}).status_code == 409
    assert db.query_one('SELECT title FROM change_plans WHERE id = ?', (pid,))['title'] == 'Renamed'


def test_cancel_is_for_the_requester_and_whoever_may_approve(estate, db):
    alice, bob = estate.admin('alice'), estate.admin('bob')
    ta = estate.tenant_holder('tadmin')
    nobody = estate.tenant_holder('nobody', perms=['changes.view', 'vm.view'])
    wide = _make(alice, 'submitted', kind='storage', targets=('local',))
    assert nobody.post(f'/api/changes/{wide}/cancel').status_code == 403
    assert ta.get(f'/api/changes/{wide}').status_code == 200
    assert ta.post(f'/api/changes/{wide}/cancel').status_code == 403     # cluster-wide: not theirs to close
    assert bob.post(f'/api/changes/{wide}/cancel').status_code == 200
    guests = _make(alice, 'submitted', kind='guests', targets=(150,))
    assert ta.post(f'/api/changes/{guests}/cancel').status_code == 200   # in their approval scope
    own = _make(alice, 'submitted')
    assert alice.post(f'/api/changes/{own}/cancel').status_code == 200
    assert [_status(db, p) for p in (wide, guests, own)] == ['cancelled'] * 3


def test_done_is_for_the_requester_or_an_approver(estate, db):
    alice, bob, carol = estate.admin('alice'), estate.admin('bob'), estate.admin('carol')
    nobody = estate.tenant_holder('nobody', perms=['changes.view', 'vm.view'])
    pid = _make(alice, 'submitted')
    assert bob.post(f'/api/changes/{pid}/approve').status_code == 200
    assert nobody.post(f'/api/changes/{pid}/done').status_code == 403
    assert carol.post(f'/api/changes/{pid}/done').status_code == 200


# -- the window -----------------------------------------------------------------------------

def _submit(estate, **kw):
    alice = estate.admin('alice')
    pid = _make(alice, **kw)
    return pid, alice.post(f'/api/changes/{pid}/submit')


def test_a_plan_cannot_be_submitted_without_a_window(estate, db):
    pid, r = _submit(estate, window_start=None, window_end=None)
    assert r.status_code == 400 and r.get_json()['code'] == 'BAD_WINDOW'
    assert _status(db, pid) == 'draft'
    _pid, r2 = _submit(estate, window_end=None)
    assert r2.status_code == 400


def test_the_window_ends_after_it_starts(estate):
    # the form refuses it when it is written ...
    r = estate.admin('alice').post('/api/changes', json=_plan_body(window_start=_iso(hours=2), window_end=_iso(hours=1)))
    assert r.status_code == 400
    # ... and a window of no length at all
    r = estate.admin('alice').post('/api/changes', json=_plan_body(window_start=_iso(hours=2), window_end=_iso(hours=2)))
    assert r.status_code == 400


def test_a_window_is_at_most_thirty_days(estate):
    _pid, ok = _submit(estate, window_start=_iso(hours=1), window_end=_iso(days=30, hours=1))
    assert ok.status_code == 200, ok.get_data(as_text=True)
    _pid, long = _submit(estate, window_start=_iso(hours=1), window_end=_iso(days=30, hours=2))
    assert long.status_code == 400 and long.get_json()['code'] == 'BAD_WINDOW'


def test_a_window_may_not_start_in_the_past_by_more_than_a_few_minutes(estate):
    _pid, late = _submit(estate, window_start=_iso(minutes=-2), window_end=_iso(hours=1))
    assert late.status_code == 200, late.get_data(as_text=True)
    _pid, past = _submit(estate, window_start=_iso(minutes=-30), window_end=_iso(hours=1))
    assert past.status_code == 400 and past.get_json()['code'] == 'BAD_WINDOW'


def test_a_window_with_an_offset_is_read_as_that_moment(estate):
    start = (datetime.now(timezone.utc) + timedelta(hours=1)).astimezone(timezone(timedelta(hours=-5)))
    end = start + timedelta(hours=1)
    r = estate.admin('alice').post('/api/changes', json=_plan_body(
        window_start=start.isoformat(), window_end=end.isoformat()))
    assert r.status_code == 201
    stored = r.get_json()['window_start']
    assert stored.endswith('Z') and changes.parse_utc(stored) == start.astimezone(timezone.utc).replace(microsecond=0)


def test_garbage_in_the_form_is_a_400(estate):
    alice = estate.admin('alice')
    for patch in ({'window_start': 'tomorrow'}, {'title': ''}, {'title': 5}, {'scope': 'all'},
                  {'scope': {'kind': 'everything', 'targets': []}},
                  {'scope': {'kind': 'guests', 'targets': []}},
                  {'scope': {'kind': 'guests', 'targets': ['abc']}},
                  {'scope': {'kind': 'guests', 'targets': [True]}},
                  {'scope': {'kind': 'storage', 'targets': [3]}},
                  {'cluster_id': None}):
        assert alice.post('/api/changes', json=_plan_body(**patch)).status_code == 400, patch
    assert alice.post('/api/changes', json=_plan_body(cluster_id='nope')).status_code == 404


def test_an_approval_after_the_window_is_over_is_refused(estate, db):
    _insert(db, 'late', status='submitted', start=_iso(hours=-3), end=_iso(hours=-1))
    bob = estate.admin('bob')
    r = bob.post('/api/changes/late/approve')
    assert r.status_code == 409 and r.get_json()['code'] == 'WINDOW_OVER'
    shown = bob.get('/api/changes/late').get_json()
    assert shown['expired'] is True and shown['display_status'] == 'expired'
    assert shown['can']['approve'] is False


def test_expired_is_derived_and_filterable(estate, db):
    _insert(db, 'old', status='approved', start=_iso(hours=-3), end=_iso(hours=-1))
    _insert(db, 'fresh', status='approved')
    _insert(db, 'fin', status='done', start=_iso(hours=-3), end=_iso(hours=-1))
    bob = estate.admin('bob')
    assert {p['id'] for p in bob.get('/api/changes?status=expired').get_json()['changes']} == {'old'}
    shown = {p['id']: p['display_status'] for p in bob.get('/api/changes').get_json()['changes']}
    assert shown == {'old': 'expired', 'fresh': 'approved', 'fin': 'done'}


# -- HA classification and the migration ----------------------------------------------------

def test_the_plans_are_replicated_and_the_drift_events_stay_per_host():
    assert 'change_plans' in ha.SYNC_TABLES and 'change_plans' not in ha.LOCAL_TABLES
    assert 'drift_events' in ha.LOCAL_TABLES


def test_an_existing_database_gets_the_column_and_the_table(db):
    db.conn.execute('DROP TABLE change_plans')
    db.conn.execute('ALTER TABLE drift_events DROP COLUMN change_id')
    db.conn.commit()
    db._init_db()
    cols = {r[1] for r in db.conn.execute('PRAGMA table_info(drift_events)').fetchall()}
    assert 'change_id' in cols
    assert db.conn.execute('SELECT COUNT(*) FROM change_plans').fetchone()[0] == 0


# -- the drift link -------------------------------------------------------------------------

LIVE = [('vm_config', 'qemu/101', {'cores': 4}),
        ('vm_config', 'qemu/102', {'cores': 4}),
        ('storage', 'local', {'content': 'iso'}),
        ('cluster_options', 'global', {'keyboard': 'de'}),
        ('network', 'pve1/vmbr0', {'address': '10.0.0.2'})]
BASE = {('vm_config', 'qemu/101'): {'cores': 2}, ('vm_config', 'qemu/102'): {'cores': 2},
        ('storage', 'local'): {'content': 'iso,backup'}, ('cluster_options', 'global'): {'keyboard': 'en'},
        ('network', 'pve1/vmbr0'): {'address': '10.0.0.1'}}


@pytest.fixture
def scanned(estate, api, db, monkeypatch):
    from pegaprox.background import alerts
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels', lambda payload: None)
    monkeypatch.setattr(alerts, '_notification_handlers', [])
    monkeypatch.setattr(drift, '_fetch_state', lambda mgr, cid: list(LIVE))
    for (kind, scope), snap in BASE.items():
        for cid in (CL, OTHER):
            db.conn.execute("INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, "
                            "created_by) VALUES (?, ?, ?, ?, ?, '2026-10-01T00:00:00', 'root')",
                            (f'{cid}-{kind}-{scope}', cid, kind, scope, json.dumps(snap)))
    db.conn.commit()

    def scan(cid=CL):
        db.conn.execute('DELETE FROM drift_events')
        db.conn.commit()
        res = drift._scan_cluster(cid)
        assert 'error' not in res, res
        return {(r['kind'], r['scope']): (r['change_id'], r['category'])
                for r in db.query('SELECT kind, scope, change_id, category FROM drift_events')}
    return scan


def test_a_deviation_inside_scope_and_window_is_planned_and_stays_a_deviation(scanned, db):
    _insert(db, 'g1', kind='guests', targets=(101,), title='Resize web')
    got = scanned()
    assert got[('vm_config', 'qemu/101')] == ('g1', 'deviation')
    # the guest the plan does not name, and every other kind, stay normal deviations
    assert got[('vm_config', 'qemu/102')] == (None, 'deviation')
    assert got[('storage', 'local')] == (None, 'deviation')
    assert got[('network', 'pve1/vmbr0')] == (None, 'deviation')


def test_outside_the_window_is_a_normal_deviation(scanned, db):
    _insert(db, 'future', kind='cluster', start=_iso(hours=1), end=_iso(hours=2))
    _insert(db, 'past', kind='cluster', start=_iso(hours=-3), end=_iso(hours=-1))
    assert {v[0] for v in scanned().values()} == {None}


def test_only_an_approved_plan_links(scanned, db):
    for i, st in enumerate(('draft', 'submitted', 'rejected', 'cancelled')):
        _insert(db, f'p{i}', status=st, kind='cluster')
    assert {v[0] for v in scanned().values()} == {None}


def test_a_plan_of_another_cluster_links_nothing(scanned, db):
    _insert(db, 'elsewhere', cluster=OTHER, kind='cluster')
    assert {v[0] for v in scanned(CL).values()} == {None}
    assert {v[0] for v in scanned(OTHER).values()} == {'elsewhere'}


def test_a_plan_of_kind_cluster_covers_every_kind(scanned, db):
    _insert(db, 'all', kind='cluster', title='Window of the quarter')
    got = scanned()
    assert {v[0] for v in got.values()} == {'all'} and len(got) == 5
    assert {v[1] for v in got.values()} == {'deviation'}


def test_the_kinds_map_to_their_plan_kinds(scanned, db):
    _insert(db, 'st', kind='storage', targets=('local',))
    _insert(db, 'nw', kind='network', targets=('pve1',))
    _insert(db, 'fw', kind='firewall')
    got = scanned()
    assert got[('storage', 'local')][0] == 'st'
    assert got[('network', 'pve1/vmbr0')][0] == 'nw'
    assert got[('cluster_options', 'global')][0] is None      # only a plan of kind cluster covers it
    assert got[('vm_config', 'qemu/101')][0] is None


def test_a_plan_for_one_storage_does_not_cover_another(scanned, db):
    _insert(db, 'st', kind='storage', targets=('ceph',))
    assert scanned()[('storage', 'local')][0] is None


def test_policy_violations_and_incidents_are_never_linked(estate, db):
    _insert(db, 'all', kind='cluster')
    pol = drift._record_event(CL, 'access', 'policy:admin_role', [], 'warning', 'x',
                              category=drift.CATEGORY_POLICY, change_id='all')
    inc = drift._record_event(CL, 'storage', 'local', [], 'warning', 'x',
                              category=drift.CATEGORY_INCIDENT, change_id='all')
    dev = drift._record_event(CL, 'storage', 'local', [], 'warning', 'x', change_id='all')
    link = lambda i: db.query_one('SELECT change_id FROM drift_events WHERE id = ?', (i,))['change_id']  # noqa: E731
    assert (link(pol), link(inc), link(dev)) == (None, None, 'all')


def test_confirming_an_incident_takes_the_link_off(estate, db):
    _insert(db, 'all', kind='cluster')
    eid = drift._record_event(CL, 'storage', 'local', [], 'warning', 'x', change_id='all')
    r = estate.admin('root').post(f'/api/drift/events/{eid}/incident', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.query_one('SELECT change_id, category FROM drift_events WHERE id = ?', (eid,))
    assert (row['change_id'], row['category']) == (None, 'incident')


def test_one_query_per_scan_not_per_event(scanned, monkeypatch):
    calls = []
    real = changes.approved_in_window
    monkeypatch.setattr(changes, 'approved_in_window', lambda *a, **k: calls.append(a) or real(*a, **k))
    got = scanned()
    assert len(got) == 5 and len(calls) == 1


def test_the_event_list_names_the_plan_and_the_status_counts_the_planned(scanned, estate, db):
    _insert(db, 'g1', kind='guests', targets=(101,), title='Resize web')
    scanned()
    root = estate.admin('root')
    events = root.get(f'/api/clusters/{CL}/drift/events?status=all').get_json()['events']
    by = {(e['kind'], e['scope']): e for e in events}
    planned = by[('vm_config', 'qemu/101')]
    assert (planned['change_id'], planned['change_title'], planned['category']) == ('g1', 'Resize web', 'deviation')
    assert 'change_title' not in by[('storage', 'local')] and by[('storage', 'local')]['change_id'] is None
    status = root.get(f'/api/clusters/{CL}/drift/status').get_json()
    assert status['planned'] == 1 and status['by_category']['deviation'] == 5


def test_a_plan_of_a_cluster_the_requester_lost_is_gone_for_them_too(estate, db):
    """Reach is judged today: a plan they wrote on a cluster that is no longer theirs is not shown."""
    _insert(db, 'mine', status='draft', cluster=OTHER, kind='guests', targets=(150,), requested_by='tadmin')
    ta = estate.tenant_holder('tadmin')
    assert ta.get('/api/changes/mine').status_code == 404
    assert ta.get('/api/changes').get_json()['changes'] == []
    assert ta.post('/api/changes/mine/cancel').status_code == 404
