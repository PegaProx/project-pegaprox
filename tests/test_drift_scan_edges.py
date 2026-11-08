"""Edges of the drift scan and its routes found in a live run.

A kind that was read but has no baseline was reported "checked" with zero events, although
nothing could be compared (a manual scan does not seed, so after an upgrade the kinds added
later have none). The same unchanged deviation was written again by every scan, removals
included, so the open list grew by the number of drifted objects per scan. A limit that is no
number answered with a 500 page, and an id that is no cluster answered 200 with zeros.

Fake PVE and fixtures are those of test_drift_more_kinds.py; events and baselines land in
the throwaway test database. MK Oct 2026
"""
import pytest

from pegaprox.api import drift

from test_drift_more_kinds import CL, pve, estate, admin, auditor, operator, _events  # noqa: F401

LATER_KINDS = ('firewall', 'ha_rules', 'backup_jobs', 'access')


def _drop_baselines(db, *kinds):
    for kind in kinds:
        db.conn.execute('DELETE FROM drift_baselines WHERE cluster_id=? AND kind=?', (CL, kind))
    db.conn.commit()


# -- a kind with no baseline is not "checked" ------------------------------------------------

def test_kinds_added_after_the_baseline_are_no_baseline_not_checked(pve, db):
    """The upgrade case: the old kinds have baselines, the later ones do not."""
    drift._scan_cluster(CL, autobaseline=True)
    _drop_baselines(db, *LATER_KINDS)
    res = drift._scan_cluster(CL)          # a manual scan does not seed
    assert res['events_count'] == 0
    for kind in LATER_KINDS:
        assert res['kinds'][kind] == 'no_baseline', kind
        assert kind in res['not_checked']
        assert res['coverage'][kind]['baselined'] == 0 and res['coverage'][kind]['scopes'] > 0
    assert res['kinds']['vm_config'] == 'checked' and res['kinds']['network'] == 'checked'
    assert 'vm_config' not in res['not_checked']
    assert res['coverage']['vm_config']['baselined'] == res['coverage']['vm_config']['scopes'] == 2


def test_a_cluster_that_was_never_seeded_has_no_baseline_for_what_it_has(pve):
    res = drift._scan_cluster(CL)
    assert res['kinds']['vm_config'] == 'no_baseline' and res['kinds']['access'] == 'no_baseline'
    # no storage at all: nothing to compare and nothing missing
    assert res['kinds']['storage'] == 'checked'
    assert 'storage' not in res['coverage']


def test_the_seeding_scan_reports_the_kinds_it_just_baselined_as_checked(pve):
    res = drift._scan_cluster(CL, autobaseline=True)
    assert res['not_checked'] == [] and res['kinds']['firewall'] == 'checked'


def test_no_baseline_wins_over_partly_read(pve):
    """Some guests answered, none has a baseline: the missing baseline is the bigger gap."""
    pve.routes['/nodes/n1/qemu/102/config'] = 500
    assert drift._scan_cluster(CL)['kinds']['vm_config'] == 'no_baseline'


def test_an_unread_kind_stays_not_checked(pve):
    pve.routes['/cluster/backup'] = 500
    assert drift._scan_cluster(CL)['kinds']['backup_jobs'] == 'not_checked'


def test_status_says_no_baseline_and_a_reset_takes_it_back(admin, operator, pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    _drop_baselines(db, *LATER_KINDS)
    drift._scan_cluster(CL)
    j = admin.get(f'/api/clusters/{CL}/drift/status').get_json()
    assert {j['kinds'][k] for k in LATER_KINDS} == {'no_baseline'}
    assert j['kinds']['storage'] == 'checked' and j['coverage']['access']['baselined'] == 0

    assert operator.post(f'/api/clusters/{CL}/drift/baseline').status_code == 200
    j = admin.get(f'/api/clusters/{CL}/drift/status').get_json()
    assert {j['kinds'][k] for k in LATER_KINDS} == {'checked'}
    assert j['coverage']['access']['baselined'] == j['coverage']['access']['scopes'] > 0


def test_the_manual_scan_route_does_not_seed_and_says_so(admin, pve):
    j = admin.post(f'/api/clusters/{CL}/drift/scan', json={}).get_json()
    assert j['seeded_baselines'] == 0 and j['kinds']['firewall'] == 'no_baseline'


# -- the same deviation is one event ---------------------------------------------------------

def test_an_unchanged_deviation_is_recorded_once(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    first = drift._scan_cluster(CL)
    assert first['events_count'] == 1 and first['already_open'] == 0
    for _ in range(3):
        again = drift._scan_cluster(CL)
        assert again['events_count'] == 0 and again['already_open'] == 1
    assert len(_events(db, kind='backup_jobs', status='open')) == 1


def test_a_removal_is_recorded_once(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'] = []
    for _ in range(3):
        res = drift._scan_cluster(CL)
        assert res['removed'] == ['job1']
    rows = _events(db, kind='backup_jobs', status='open')
    assert len(rows) == 1 and 'object removed' in db.conn.execute(
        'SELECT summary FROM drift_events WHERE cluster_id=? AND kind=?', (CL, 'backup_jobs')).fetchone()[0]


def test_a_changed_diff_is_a_new_event(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    drift._scan_cluster(CL)
    pve.routes['/cluster/backup'][0]['schedule'] = 'monthly'
    assert drift._scan_cluster(CL)['events_count'] == 1
    assert len(_events(db, kind='backup_jobs', status='open')) == 2


def test_a_repeat_raises_no_alert(pve):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['enabled'] = 0
    drift._scan_cluster(CL)
    sent = len(pve.sent)
    assert sent == 1
    drift._scan_cluster(CL)
    assert len(pve.sent) == sent, 'nothing new, nothing sent'


def test_the_same_diff_of_another_cluster_or_scope_hides_nothing(pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    drift._scan_cluster(CL)
    # the identical row, moved to another cluster, and to another scope of this one
    db.conn.execute("UPDATE drift_events SET cluster_id='elsewhere' WHERE cluster_id=?", (CL,))
    db.conn.execute("INSERT INTO drift_events (cluster_id, kind, scope, severity, summary, diff, "
                    "detected_at, status, category) SELECT ?, kind, 'job2', severity, summary, diff, "
                    "detected_at, status, category FROM drift_events", (CL,))
    db.conn.commit()
    assert drift._scan_cluster(CL)['events_count'] == 1


def test_an_acknowledged_event_no_longer_counts_as_open(admin, pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    eid = drift._scan_cluster(CL)['events'][0]['id']
    assert admin.post(f'/api/drift/events/{eid}/acknowledge', json={}).status_code == 200
    # the baseline still differs, so the next scan has news for the one who acknowledged
    assert drift._scan_cluster(CL)['events_count'] == 1


def test_a_confirmed_incident_is_the_same_event(admin, pve, db):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    eid = drift._scan_cluster(CL)['events'][0]['id']
    assert admin.post(f'/api/drift/events/{eid}/incident', json={}).status_code == 200
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 0 and len(_events(db, kind='backup_jobs')) == 1


def test_a_failed_read_of_the_open_events_records_as_before(pve, db, monkeypatch):
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/backup'][0]['schedule'] = 'weekly'
    drift._scan_cluster(CL)
    monkeypatch.setattr(drift, '_open_deviation_diffs', lambda cluster_id: set())
    assert drift._scan_cluster(CL)['events_count'] == 1


# -- the events limit ------------------------------------------------------------------------

@pytest.mark.parametrize('limit', ['abc', '', '1.5', '0', '-3'])
def test_a_bad_limit_is_a_400(admin, pve, limit):
    r = admin.get(f'/api/clusters/{CL}/drift/events?limit={limit}')
    assert r.status_code == 400, (limit, r.status_code)
    assert 'limit' in r.get_json()['error']


@pytest.mark.parametrize('limit', ['1', '100', '500', '501', '99999999999999999999'])
def test_a_limit_inside_the_range_is_taken(admin, pve, db, limit):
    r = admin.get(f'/api/clusters/{CL}/drift/events?limit={limit}')
    assert r.status_code == 200 and r.get_json() == {'events': []}


def test_the_limit_still_cuts_the_list(admin, pve, db):
    for i in range(1, 6):
        db.conn.execute("INSERT INTO drift_events (id, cluster_id, kind, scope, severity, summary, diff, "
                        "detected_at, status, category) VALUES (?, ?, 'access', 'acl', 'warning', 's', '[]', "
                        "'2026-10-02T00:00:00', 'open', 'deviation')", (i, CL))
    db.conn.commit()
    assert len(admin.get(f'/api/clusters/{CL}/drift/events?limit=2').get_json()['events']) == 2
    assert len(admin.get(f'/api/clusters/{CL}/drift/events').get_json()['events']) == 5


# -- an id that is no cluster ----------------------------------------------------------------

GHOST = 'nope'


@pytest.mark.parametrize('method,path', [
    ('get', '/api/clusters/nope/drift/status'),
    ('get', '/api/clusters/nope/drift/events'),
    ('get', '/api/clusters/nope/drift/policy'),
    ('post', '/api/clusters/nope/drift/scan'),
    ('put', '/api/clusters/nope/drift/policy'),
    ('post', '/api/clusters/nope/drift/baseline'),
])
def test_an_unknown_cluster_is_a_404(admin, pve, method, path):
    kw = {'json': {'checks': {'access_admin_role': {'enabled': True}}}} if method == 'put' else {}
    r = getattr(admin, method)(path, **kw)
    assert r.status_code == 404, (path, r.status_code, r.get_data(as_text=True)[:200])
    assert 'not found' in r.get_json()['error']


def test_an_unknown_cluster_stores_no_policy(admin, pve, db):
    admin.put(f'/api/clusters/{GHOST}/drift/policy', json={'checks': {'access_admin_role': {'enabled': True}}})
    assert all(not c['enabled'] for c in drift._policy_view(GHOST)[0])


def test_a_known_cluster_still_answers(admin, pve):
    for path in ('status', 'events', 'policy'):
        assert admin.get(f'/api/clusters/{CL}/drift/{path}').status_code == 200
    assert admin.post(f'/api/clusters/{CL}/drift/scan', json={}).status_code == 200


def test_the_404_does_not_tell_a_caller_who_may_not_reach_it(auditor, pve):
    """The access gate comes first: an id the caller has no access to is a 403 whether or not
    it exists, so the answer says nothing about which ids there are."""
    assert auditor.get(f'/api/clusters/{GHOST}/drift/events').status_code == 403
    assert auditor.get(f'/api/clusters/{GHOST}/drift/policy').status_code == 403
    assert auditor.post(f'/api/clusters/{GHOST}/drift/scan', json={}).status_code == 403
