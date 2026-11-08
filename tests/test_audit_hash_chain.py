"""The audit log as a hash chain.

Every row carried an HMAC, which catches a row that was changed and nothing else: delete a
row, or the newest fifty, and every row left still verifies. Rows now carry their number in
a chain and the hash of the row before it, under the same HMAC, and signed checkpoints say
how far the chain went, including how far retention cut it. MK Oct 2026
"""
import gevent
import pytest

from pegaprox.core import ha


def _add(db, n, prefix='e'):
    for i in range(n):
        db.add_audit_entry('alice', f'test.{prefix}{i}', f'{prefix} {i}', '10.0.0.1', 'c1', 'info')


def _rows(db):
    return [dict(r) for r in db.conn.execute(
        'SELECT * FROM audit_log WHERE chain_seq IS NOT NULL ORDER BY chain_seq')]


def test_rows_form_one_chain_from_the_genesis(db):
    _add(db, 5)
    rows = _rows(db)
    genesis = dict(db.conn.execute("SELECT * FROM audit_checkpoints WHERE kind = 'genesis'").fetchone())
    assert [r['chain_seq'] for r in rows] == [1, 2, 3, 4, 5]
    assert rows[0]['prev_hash'] == genesis['row_hash']
    for a, b in zip(rows, rows[1:]):
        assert b['prev_hash'] == db._audit_row_hash(a)
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True, res
    assert res['chain']['rows'] == 5 and res['verified'] == 5
    assert res['chain']['missing'] == 0 and res['chain']['broken_links'] == 0


def test_an_edited_row_is_named_without_blaming_the_next_link(db):
    _add(db, 4)
    db.conn.execute("UPDATE audit_log SET details = 'nothing happened' WHERE chain_seq = 2")
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False
    assert res['chain']['edited'] == 1 and res['chain']['edited_seqs'] == [2]
    assert res['potentially_tampered'] == 1
    assert res['chain']['broken_links'] == 0


def test_a_deleted_row_is_reported_missing(db):
    """The case the HMAC alone could never see: every row left verifies."""
    _add(db, 6)
    db.conn.execute('DELETE FROM audit_log WHERE chain_seq IN (3, 4)')
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['potentially_tampered'] == 0          # what the old check reported
    assert res['intact'] is False
    assert res['chain']['missing'] == 2
    assert res['chain']['missing_ranges'] == [[3, 4]]


def test_a_moved_prev_hash_is_a_broken_link_even_with_a_valid_signature(db):
    _add(db, 3)
    row = _rows(db)[2]
    row['prev_hash'] = 'f' * 64
    db.conn.execute('UPDATE audit_log SET prev_hash = ?, hmac_signature = ? WHERE id = ?',
                    (row['prev_hash'], db._audit_chain_hmac(row), row['id']))
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['chain']['edited'] == 0
    assert res['chain']['broken_links'] == 1 and res['chain']['broken_link_seqs'] == [3]


def test_a_tail_cut_below_the_last_checkpoint_shows(db):
    """Deleting the newest rows leaves no hole in the numbers; the checkpoint remembers."""
    _add(db, 5)
    cp = db.audit_checkpoint()
    assert cp['chain_seq'] == 5 and cp['kind'] == 'periodic'
    assert db.audit_checkpoint() is None              # nothing new since
    db.conn.execute('DELETE FROM audit_log WHERE chain_seq >= 4')
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['chain']['truncated'] is True
    assert res['chain']['missing'] == 2 and res['chain']['missing_ranges'] == [[4, 5]]
    # the next row does not reuse the numbers that were cut away
    _add(db, 1, 'after')
    assert _rows(db)[-1]['chain_seq'] == 6


def test_rows_after_the_last_checkpoint_are_counted(db):
    _add(db, 3)
    db.audit_checkpoint()
    _add(db, 2, 'late')
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True
    assert res['chain']['after_checkpoint'] == 2
    assert res['chain']['last_checkpoint']['seq'] == 3


def test_retention_prune_is_not_tampering(db):
    _add(db, 6)
    db.conn.execute("UPDATE audit_log SET timestamp = '2020-01-01T00:00:00' WHERE chain_seq <= 4")
    # re-sign: the timestamps are part of the signed body (a test shortcut for old rows)
    for r in _rows(db)[:4]:
        db.conn.execute('UPDATE audit_log SET hmac_signature = ? WHERE id = ?',
                        (db._audit_chain_hmac(r), r['id']))
    # their hashes moved with the timestamps, relink the rows after them
    rows = _rows(db)
    for a, b in zip(rows, rows[1:]):
        b['prev_hash'] = db._audit_row_hash(a)
        db.conn.execute('UPDATE audit_log SET prev_hash = ?, hmac_signature = ? WHERE id = ?',
                        (b['prev_hash'], db._audit_chain_hmac(b), b['id']))
    db.conn.commit()
    assert db.verify_audit_log_integrity()['intact'] is True
    h4 = db._audit_row_hash(_rows(db)[3])

    assert db.cleanup_audit_log(days=30) == 4

    cp = dict(db.conn.execute("SELECT * FROM audit_checkpoints WHERE kind = 'prune'").fetchone())
    assert cp['chain_seq'] == 4 and cp['row_hash'] == h4 and cp['pruned_rows'] == 4
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True, res
    assert res['chain']['missing'] == 0 and res['chain']['pruned_through'] == 4
    _add(db, 1, 'after')
    assert db.verify_audit_log_integrity()['intact'] is True


def _backdate(db, upto, ts='2020-01-01T00:00:00'):
    """Rows 1..upto as if written at ts: re-signed and relinked as the app would have
    written them (retention only takes rows that verify)"""
    rows = _rows(db)
    for r in rows[:upto]:
        r['timestamp'] = ts
    for a, b in zip(rows, rows[1:]):
        b['prev_hash'] = db._audit_row_hash(a)
    for r in rows:
        db.conn.execute('UPDATE audit_log SET timestamp = ?, prev_hash = ?, hmac_signature = ? '
                        'WHERE id = ?', (r['timestamp'], r['prev_hash'], db._audit_chain_hmac(r), r['id']))
    db.conn.commit()


def test_a_prune_of_the_whole_chain_keeps_the_next_row_linked(db):
    _add(db, 3)
    _backdate(db, 3)
    tail_hash = db._audit_row_hash(_rows(db)[-1])
    db.prune_audit_log('2021-01-01T00:00:00')
    assert _rows(db) == []
    _add(db, 1, 'next')
    row = _rows(db)[0]
    assert row['chain_seq'] == 4 and row['prev_hash'] == tail_hash


def test_rows_from_before_the_chain_are_legacy_and_watched(db):
    """An upgraded install: the rows it had start the chain through the genesis digest."""
    for i in range(3):
        db.conn.execute("INSERT INTO audit_log (timestamp, user, action, details, ip_address, "
                        "hmac_signature) VALUES (?, 'bob', 'old.thing', ?, '', '')",
                        (f'2026-01-0{i + 1}T00:00:00', f'old {i}'))
    db.conn.execute('DELETE FROM audit_checkpoints')
    db.conn.commit()
    db._ensure_audit_genesis()
    _add(db, 2)
    res = db.verify_audit_log_integrity()
    assert res['legacy']['rows'] == 3 and res['legacy']['unsigned'] == 3
    assert res['legacy']['changed_since_chain_start'] is False
    assert res['chain']['rows'] == 2 and res['intact'] is True

    db.conn.execute("DELETE FROM audit_log WHERE action = 'old.thing' AND details = 'old 1'")
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['legacy']['changed_since_chain_start'] is True
    assert res['intact'] is False


def _legacy(db, *stamps):
    for i, ts in enumerate(stamps):
        db.conn.execute("INSERT INTO audit_log (timestamp, user, action, details, ip_address, "
                        "hmac_signature) VALUES (?, 'bob', 'old.thing', ?, '', '')", (ts, f'old {i}'))
    db.conn.execute('DELETE FROM audit_checkpoints')
    db.conn.commit()
    db._ensure_audit_genesis()


def test_a_prune_of_legacy_rows_only_keeps_the_chain_base(db):
    _legacy(db, '2020-01-01T00:00:00', '2020-02-01T00:00:00', '2026-01-01T00:00:00')
    genesis = dict(db.conn.execute("SELECT * FROM audit_checkpoints WHERE kind = 'genesis'").fetchone())
    _add(db, 2)
    cp = db.prune_audit_log('2021-01-01T00:00:00')
    assert cp['pruned_rows'] == 2 and cp['legacy_count'] == 1
    assert (cp['chain_seq'], cp['row_hash']) == (0, genesis['row_hash'])
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True, res
    assert res['legacy']['rows'] == 1 and res['legacy']['changed_since_chain_start'] is False


def test_a_forged_base_is_not_carried_into_a_new_signature(db):
    """A prune signs a new base from the last one it can trust. With none left (the only
    base fails its signature) it signs nothing and deletes nothing: a new base signed now
    would vouch for whatever the forgery says."""
    _legacy(db, '2026-01-01T00:00:00')
    _add(db, 3)
    _backdate(db, 1)
    db.conn.execute("UPDATE audit_checkpoints SET legacy_digest = 'forged' WHERE kind = 'genesis'")
    db.conn.commit()
    assert db.prune_audit_log('2021-01-01T00:00:00') is None
    assert db.conn.execute("SELECT COUNT(*) FROM audit_checkpoints WHERE kind = 'prune'").fetchone()[0] == 0
    assert len(_rows(db)) == 3
    assert db.verify_audit_log_integrity()['intact'] is False


def test_a_prune_stops_at_a_row_that_fails_its_signature(db):
    """Retention takes the unbroken run of old rows that verify; the first one changed
    stays, and so does everything after it."""
    _add(db, 5)
    _backdate(db, 5)
    db.conn.execute("UPDATE audit_log SET details = 'rewritten' WHERE chain_seq = 3")
    db.conn.commit()
    cp = db.prune_audit_log('2021-01-01T00:00:00')
    assert cp['chain_seq'] == 2 and cp['pruned_rows'] == 2 and cp['cutoff'] == '2021-01-01T00:00:00'
    assert [r['chain_seq'] for r in _rows(db)] == [3, 4, 5]
    res = db.verify_audit_log_integrity()
    assert res['chain']['edited_seqs'] == [3] and res['intact'] is False


def test_checkpoints_are_numbered_and_linked(db):
    _add(db, 2)
    db.audit_checkpoint()
    _add(db, 2, 'more')
    db.audit_checkpoint()
    cps = [dict(r) for r in db.conn.execute('SELECT * FROM audit_checkpoints ORDER BY cp_seq')]
    assert [c['cp_seq'] for c in cps] == [1, 2, 3] and cps[0]['kind'] == 'genesis'
    for a, b in zip(cps, cps[1:]):
        assert b['prev_cp_hash'] == db._checkpoint_hash(a)
    # one in the middle goes: a hole in the checkpoints' numbers
    db.conn.execute('DELETE FROM audit_checkpoints WHERE cp_seq = 2')
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['chain']['checkpoints_missing'] == 1 and res['intact'] is False


def test_the_newest_checkpoint_is_kept_beside_the_key(db):
    import json
    import os
    _add(db, 3)
    cp = db.audit_checkpoint()
    with open(db._audit_anchor_file) as fh:
        anchor = json.load(fh)
    assert anchor['cp_seq'] == cp['cp_seq'] and anchor['chain_seq'] == 3
    assert os.path.dirname(db._audit_anchor_file) == os.path.dirname(db.db_path)
    res = db.verify_audit_log_integrity()
    assert res['chain']['anchor'] == 'ok' and res['chain']['anchor_seq'] == 3 and res['intact'] is True
    # a forged anchor is not believed, and says so
    anchor['chain_seq'] = 1
    with open(db._audit_anchor_file, 'w') as fh:
        json.dump(anchor, fh)
    res = db.verify_audit_log_integrity()
    assert res['chain']['anchor'] == 'bad' and res['intact'] is False


def test_a_missing_anchor_is_reported_and_comes_back(db):
    import os
    _add(db, 2)
    os.remove(db._audit_anchor_file)
    res = db.verify_audit_log_integrity()
    assert res['chain']['anchor'] == 'missing' and res['intact'] is True
    db.audit_checkpoint()
    assert db.verify_audit_log_integrity()['chain']['anchor'] == 'ok'


def test_the_anchor_does_not_follow_a_chain_cut_below_it(db):
    """Cut the end and its checkpoint, write on: the next checkpoint does not move the
    anchor past the hole it vouches for."""
    _add(db, 3)
    db.audit_checkpoint()
    _add(db, 3, 'late')
    db.audit_checkpoint()
    db.conn.execute('DELETE FROM audit_log WHERE chain_seq > 3')
    db.conn.execute('DELETE FROM audit_checkpoints WHERE chain_seq > 3')
    db.conn.commit()
    _add(db, 2, 'after')
    db.audit_checkpoint()
    db.audit_checkpoint()
    _add(db, 1, 'later')
    db.audit_checkpoint()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False and res['chain']['checkpoints_broken'] >= 1, res['chain']


def test_a_new_chain_over_a_deleted_one_is_not_believed(db):
    """Delete every row and checkpoint: the next write starts a chain of its own and signs
    it. The anchor still names the old one."""
    _add(db, 3)
    db.audit_checkpoint()
    db.conn.execute('DELETE FROM audit_log')
    db.conn.execute('DELETE FROM audit_checkpoints')
    db.conn.commit()
    _add(db, 2, 'fresh')
    db.audit_checkpoint()
    res = db.verify_audit_log_integrity()
    assert res['chain']['restarted'] is True and res['intact'] is False


def test_concurrent_writers_keep_the_chain_linear(db):
    """Greenlets with connections of their own, and OS threads from the hub's pool."""
    def burst(tag):
        for i in range(15):
            db.add_audit_entry('w', f'test.{tag}', str(i))
    lets = [gevent.spawn(burst, f'g{k}') for k in range(6)]
    pool = gevent.get_hub().threadpool
    native = [pool.spawn(burst, f't{k}') for k in range(3)]
    gevent.joinall(lets, raise_error=True)
    for r in native:
        r.get()
    seqs = [r['chain_seq'] for r in _rows(db)]
    assert seqs == list(range(1, 136))
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True and res['chain']['rows'] == 135


def test_a_pending_write_on_the_connection_is_committed_with_the_row(db):
    """add_audit_entry used to commit whatever the caller had pending; it still does."""
    db.conn.execute("INSERT INTO server_settings (key, value) VALUES ('chain_probe', '1')")
    assert db.conn.in_transaction
    db.add_audit_entry('alice', 'test.pending', 'x')
    assert not db.conn.in_transaction
    assert db.verify_audit_log_integrity()['intact'] is True


def test_key_rotation_keeps_chain_and_checkpoints_verifying(db):
    _add(db, 3)
    db.audit_checkpoint()
    res = db.rotate_encryption_key()
    assert not res.get('errors'), res
    out = db.verify_audit_log_integrity()
    assert out['intact'] is True, out
    assert out['chain']['bad_checkpoints'] == 0


def test_a_forged_checkpoint_is_not_believed(db):
    _add(db, 3)
    db.audit_checkpoint()
    db.conn.execute("UPDATE audit_checkpoints SET chain_seq = 2 WHERE kind = 'periodic'")
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['chain']['bad_checkpoints'] == 1 and res['intact'] is False


def test_spot_check_window(db):
    _add(db, 10)
    db.conn.execute('DELETE FROM audit_log WHERE chain_seq = 9')
    db.conn.commit()
    res = db.verify_audit_log_integrity(limit=4)
    assert res['scanned_limit'] == 4
    assert res['chain']['missing'] == 1 and res['legacy'] is None


def test_checkpoints_go_to_the_siem_targets_as_their_own_event(db, monkeypatch):
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', lambda ev: sent.append(ev))
    _add(db, 2)
    sent.clear()
    db.audit_checkpoint()
    assert sent == []                                  # no target, nothing queued

    db.conn.execute("INSERT INTO siem_targets (id, name, type, endpoint, enabled, created_at) "
                    "VALUES ('t1', 'x', 'http_json', 'https://siem.example/x', 1, '2026-10-10')")
    db.conn.commit()
    _add(db, 1, 'more')
    sent.clear()
    cp = db.audit_checkpoint()
    assert len(sent) == 1
    ev = sent[0]
    assert ev['event_type'] == 'audit_checkpoint' and ev['action'] == 'audit.checkpoint'
    assert ev['checkpoint']['chain_seq'] == cp['chain_seq'] == 3
    assert ev['checkpoint']['row_hash'] == cp['row_hash']
    line = siem._to_json_line(ev)
    assert line['event_type'] == 'audit_checkpoint' and line['checkpoint']['chain_seq'] == 3


def test_every_forwarded_entry_carries_its_place_in_the_chain(db, monkeypatch):
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', lambda ev: sent.append(ev))
    db.add_audit_entry('alice', 'vm.start', 'started 100')
    row = _rows(db)[-1]
    line = siem._to_json_line(sent[-1])
    assert line['chain_seq'] == row['chain_seq'] and line['chain_hash'] == db._audit_row_hash(row)
    assert line['event_type'] == 'audit'


def test_the_checkpoint_table_is_instance_local():
    assert 'audit_checkpoints' in ha.LOCAL_TABLES and 'audit_checkpoints' not in ha.SYNC_TABLES


def test_hourly_checkpoint_runs_on_a_standby_too(db, monkeypatch):
    """audit_log is per instance: a standby's own logins and refusals are its chain."""
    import pegaprox.background.alerts as alerts
    calls = []
    monkeypatch.setattr('pegaprox.utils.audit.checkpoint_audit_log', lambda: calls.append(1))
    monkeypatch.setattr(alerts, '_last_audit_checkpoint_at', 0.0)
    alerts._periodic_audit_checkpoint()
    alerts._periodic_audit_checkpoint()          # within the hour: not again
    assert calls == [1]


# ---- the route --------------------------------------------------------------------------

def test_integrity_route_reports_the_chain(api, seed):
    admin = seed.user('root_admin', role='admin')
    _add(seed.db, 3)
    seed.db.conn.execute('DELETE FROM audit_log WHERE chain_seq = 2')
    seed.db.conn.commit()
    r = api.as_user(admin).get('/api/audit/integrity')
    assert r.status_code == 200
    body = r.get_json()
    assert body['chain']['missing'] == 1 and body['intact'] is False
    assert 'legacy' in body


@pytest.mark.parametrize('who', ['plain', 'confined_admin', 'other_tenant'])
def test_integrity_route_needs_admin_audit(api, seed, who):
    seed.tenant('acme', clusters=['cluster_1'])
    if who == 'plain':
        u = seed.user('pat', role='user')
    elif who == 'confined_admin':
        u = seed.user('tadmin', role='admin', tenant_id='acme',
                      tenant_permissions={'acme': {'role': 'viewer'}})
    else:
        u = seed.user('olga', role='user', tenant_id='acme')
    r = api.as_user(u).get('/api/audit/integrity')
    assert r.status_code == 403
