"""Rewriting a drift baseline needs more than the permission to read drift.

Reset baseline, a scan with seed and an acknowledge with promote each store the
cluster's current configuration as the accepted one, so the change stops being flagged
(reset also supersedes every open event). All three asked for admin.audit only, "View
audit logs", which the Auditor and Monitoring role templates carry: a read-only auditor
could make configuration drift disappear. They now also need cluster.config, the
permission to change the cluster's settings in the first place.

Reading drift, scanning for it and acknowledging an event (the row stays, with who
acknowledged it) remain the auditor's.
"""
import json

import pytest

from pegaprox.api import drift

CL = 'cluster_1'
LIVE = [('storage', 'local', {'type': 'dir', 'content': 'iso'}),
        ('cluster_options', 'cluster', {'keyboard': 'de'})]


@pytest.fixture
def estate(api, seed, db, monkeypatch):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    m = api.make_fake_manager(CL)
    m.is_connected = True
    api.set_manager(CL, m)
    monkeypatch.setattr(drift, '_fetch_state', lambda mgr, cid: list(LIVE))
    # a scan that finds drift notifies; nothing leaves the test
    from pegaprox.background import alerts
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels', lambda payload: None)
    monkeypatch.setattr(alerts, '_notification_handlers', [])
    db.conn.execute("INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, created_by) "
                    "VALUES ('b1', ?, 'storage', 'local', ?, '2026-10-01T00:00:00', 'root')",
                    (CL, json.dumps({'type': 'dir', 'content': 'iso,backup'})))
    db.conn.execute("INSERT INTO drift_events (id, cluster_id, kind, scope, severity, summary, diff, detected_at, status) "
                    "VALUES (7, ?, 'storage', 'local', 'warning', 'content changed', '[]', '2026-10-02T00:00:00', 'open')",
                    (CL,))
    db.conn.commit()
    return seed


def _baselines(db):
    return {(r['kind'], r['scope']): json.loads(r['snapshot'])
            for r in db.query('SELECT kind, scope, snapshot FROM drift_baselines WHERE cluster_id = ?', (CL,))}


def _event(db):
    return db.query('SELECT status, acknowledged_by FROM drift_events WHERE id = 7')[0]


@pytest.fixture
def auditor(api, estate):
    """The Auditor template's grant: read-only plus admin.audit, cluster-wide, unconfined."""
    return api.as_user(estate.user('aud', role='viewer', tenant_id='t', permissions=['admin.audit']))


@pytest.fixture
def operator(api, estate):
    return api.as_user(estate.user('op', role='viewer', tenant_id='t',
                                   permissions=['admin.audit', 'cluster.config']))


def test_an_auditor_cannot_reset_the_baseline(auditor, db):
    before = _baselines(db)
    r = auditor.post(f'/api/clusters/{CL}/drift/baseline')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert _baselines(db) == before and _event(db)['status'] == 'open'


def test_an_auditor_cannot_seed_a_baseline_with_a_scan(auditor, db):
    r = auditor.post(f'/api/clusters/{CL}/drift/scan', json={'seed': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert ('cluster_options', 'cluster') not in _baselines(db)


def test_an_auditor_cannot_promote_an_event(auditor, db):
    before = _baselines(db)
    r = auditor.post('/api/drift/events/7/acknowledge', json={'promote': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert _baselines(db) == before and _event(db)['status'] == 'open'


def test_an_auditor_still_reads_scans_and_acknowledges(auditor, db):
    assert auditor.get(f'/api/clusters/{CL}/drift/events').status_code == 200
    scan = auditor.post(f'/api/clusters/{CL}/drift/scan', json={})
    assert scan.status_code == 200 and scan.get_json()['seeded_baselines'] == 0, scan.get_data(as_text=True)
    ack = auditor.post('/api/drift/events/7/acknowledge', json={})
    assert ack.status_code == 200, ack.get_data(as_text=True)
    assert dict(_event(db)) == {'status': 'acknowledged', 'acknowledged_by': 'aud'}


def test_whoever_may_change_the_cluster_rewrites_the_baseline(operator, db):
    r = operator.post('/api/drift/events/7/acknowledge', json={'promote': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _baselines(db)[('storage', 'local')] == {'type': 'dir', 'content': 'iso'}
    assert operator.post(f'/api/clusters/{CL}/drift/scan', json={'seed': True}).get_json()['seeded_baselines'] == 1
    reset = operator.post(f'/api/clusters/{CL}/drift/baseline')
    assert reset.status_code == 200 and reset.get_json()['baselines'] == 2, reset.get_data(as_text=True)


def test_an_admin_resets_as_before(api, estate, db):
    r = api.as_user(estate.user('root', role='admin')).post(f'/api/clusters/{CL}/drift/baseline')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert set(_baselines(db)) == {('storage', 'local'), ('cluster_options', 'cluster')}


def test_a_policy_violation_is_acknowledged_by_whoever_may_change_the_cluster(auditor, operator, db):
    # acknowledged, it is not raised again while the offenders stay the same
    db.conn.execute("UPDATE drift_events SET category = 'policy_violation' WHERE id = 7")
    db.conn.commit()
    r = auditor.post('/api/drift/events/7/acknowledge', json={})
    assert r.status_code == 403 and 'policy violation' in r.get_json()['error'], r.get_data(as_text=True)
    assert _event(db)['status'] == 'open'
    assert operator.post('/api/drift/events/7/acknowledge', json={}).status_code == 200
    assert dict(_event(db)) == {'status': 'acknowledged', 'acknowledged_by': 'op'}
