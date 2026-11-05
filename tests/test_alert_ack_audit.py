"""Acknowledging a firing alert leaves an audit entry.

POST /api/clusters/<id>/active-alerts/<incident>/ack stops the escalation of an incident: who
did that and when is what an audit is for. The mute routes next to it wrote one, the ack did
not, so an incident that was silenced by an ack could not be traced to anyone in the audit
log (the row itself only keeps the last acked_by). There is no route that takes an ack back.
"""
CID = 'c1'


def _incident(db, iid='i-1', cluster=CID, message='CPU on pve1 is 97% (> 90)', resolved=None):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, message, triggered_at, resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (iid, f'r1:{cluster}:pve1', 'r1', cluster, 'cpu', 'node', 'pve1', 'pve1', message,
         '2026-11-01T08:00:00', resolved))
    db.conn.commit()


def _audit(db, action='alert.acknowledged'):
    return [dict(r) for r in db.conn.execute(
        "SELECT user, action, details, cluster, cluster_id FROM audit_log WHERE action = ?", (action,))]


def _admin(api, seed):
    api.set_manager(CID, api.make_fake_manager(CID))
    return api.as_user(seed.user('root', role='admin'))


def test_an_ack_is_audited_with_who_what_and_where(api, seed, db):
    _incident(db)
    r = _admin(api, seed).post(f'/api/clusters/{CID}/active-alerts/i-1/ack')
    assert r.status_code == 200 and r.get_json()['acked_by'] == 'root'
    row, = _audit(db)
    assert row['user'] == 'root'
    assert row['action'] == 'alert.acknowledged'
    assert row['cluster'] == CID and row['cluster_id'] == CID
    # the incident and what it said, as the mute routes name what they muted
    assert row['details'] == 'Acknowledged incident i-1: CPU on pve1 is 97% (> 90) [c1]'
    # the incident row itself is acked as before
    acked = db.conn.execute("SELECT acked_by, acked_at FROM active_alerts WHERE id = 'i-1'").fetchone()
    assert acked['acked_by'] == 'root' and acked['acked_at']


def test_an_ack_that_found_nothing_is_not_audited(api, seed, db):
    _incident(db, iid='i-done', resolved='2026-11-01T09:00:00')
    _incident(db, iid='i-other', cluster='c2')
    c = _admin(api, seed)
    assert c.post(f'/api/clusters/{CID}/active-alerts/i-missing/ack').status_code == 404
    assert c.post(f'/api/clusters/{CID}/active-alerts/i-done/ack').status_code == 404
    # an incident of another cluster is not reached through this cluster's route
    assert c.post(f'/api/clusters/{CID}/active-alerts/i-other/ack').status_code == 404
    assert _audit(db) == []


def test_an_ack_without_the_permission_is_refused_and_not_audited(api, seed, db):
    _incident(db)
    api.set_manager(CID, api.make_fake_manager(CID))
    viewer = api.as_user(seed.user('viewer1', role='viewer'))
    assert viewer.post(f'/api/clusters/{CID}/active-alerts/i-1/ack').status_code == 403
    assert _audit(db) == []
    assert db.conn.execute("SELECT acked_by FROM active_alerts WHERE id = 'i-1'").fetchone()['acked_by'] is None
